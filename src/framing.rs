use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use hyper::rt::{Read, ReadBuf, ReadBufCursor, Write};
use pin_project_lite::pin_project;

const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[derive(Clone, Debug)]
pub struct FramingGuardControl {
    disabled: Arc<AtomicBool>,
}

impl FramingGuardControl {
    pub fn disable(&self) {
        self.disabled.store(true, Ordering::Release);
    }
}

pin_project! {
    #[derive(Debug)]
    pub struct FramingGuardIo<T> {
        #[pin]
        inner: T,
        parser: FramingParser,
        pending: Vec<u8>,
        pending_position: usize,
        read_buffer: Vec<u8>,
        disabled: Arc<AtomicBool>,
        rejected: bool,
        response_position: usize,
        response_flushed: bool,
    }
}

impl<T> FramingGuardIo<T> {
    pub fn new(inner: T, max_header_bytes: usize) -> Self {
        Self {
            inner,
            parser: FramingParser::new(max_header_bytes),
            pending: Vec::new(),
            pending_position: 0,
            read_buffer: Vec::new(),
            disabled: Arc::new(AtomicBool::new(false)),
            rejected: false,
            response_position: 0,
            response_flushed: false,
        }
    }

    pub fn control(&self) -> FramingGuardControl {
        FramingGuardControl {
            disabled: Arc::clone(&self.disabled),
        }
    }

    pub fn disable(&mut self) {
        self.disabled.store(true, Ordering::Release);
    }

    /// Test/fuzz access to the wrapped transport (the field itself stays
    /// private so production paths cannot bypass the guard).
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Consume the guard and return the wrapped transport (fuzz/test use).
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Read + Write> Read for FramingGuardIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut buffer: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if *this.rejected {
            return poll_rejection(
                this.inner,
                context,
                this.response_position,
                this.response_flushed,
            );
        }
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if *this.pending_position < this.pending.len() {
            let count = buffer
                .remaining()
                .min(this.pending.len() - *this.pending_position);
            buffer.put_slice(&this.pending[*this.pending_position..*this.pending_position + count]);
            *this.pending_position += count;
            if *this.pending_position == this.pending.len() {
                this.pending.clear();
                *this.pending_position = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if this.disabled.load(Ordering::Acquire) {
            return this.inner.poll_read(context, buffer);
        }

        loop {
            let read_size = this
                .parser
                .body_bytes_remaining()
                .unwrap_or(usize::MAX)
                .min(buffer.remaining());
            this.read_buffer.resize(read_size, 0);
            let mut staged = ReadBuf::new(this.read_buffer.as_mut_slice());
            match this.inner.as_mut().poll_read(context, staged.unfilled()) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let bytes = staged.filled();
                    if bytes.is_empty() {
                        this.parser.header_incomplete = false;
                    } else {
                        if this.parser.consume(bytes).is_err() {
                            *this.rejected = true;
                            this.pending.clear();
                            return poll_rejection(
                                this.inner,
                                context,
                                this.response_position,
                                this.response_flushed,
                            );
                        }
                        this.pending.extend_from_slice(bytes);
                    }
                    if this.parser.header_incomplete {
                        continue;
                    }
                    let count = buffer.remaining().min(this.pending.len());
                    buffer.put_slice(&this.pending[..count]);
                    *this.pending_position = count;
                    if count == this.pending.len() {
                        this.pending.clear();
                        *this.pending_position = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<T: Write> Write for FramingGuardIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(context, buffers)
    }
}

fn poll_rejection<T: Write>(
    mut inner: Pin<&mut T>,
    context: &mut Context<'_>,
    response_position: &mut usize,
    response_flushed: &mut bool,
) -> Poll<io::Result<()>> {
    while *response_position < BAD_REQUEST.len() {
        match inner
            .as_mut()
            .poll_write(context, &BAD_REQUEST[*response_position..])
        {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write framing rejection response",
                )));
            }
            Poll::Ready(Ok(written)) => *response_position += written,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
    }

    if !*response_flushed {
        match inner.poll_flush(context) {
            Poll::Ready(Ok(())) => *response_flushed = true,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
    }

    Poll::Ready(Ok(()))
}

#[derive(Debug)]
struct FramingParser {
    max_header_bytes: usize,
    state: RequestState,
    line: Vec<u8>,
    header_incomplete: bool,
}

#[derive(Clone, Copy, Debug)]
enum RequestState {
    Header,
    FixedBody(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkDataEnd,
    Trailers,
}

#[derive(Clone, Copy, Debug)]
enum RequestBody {
    None,
    Fixed(u64),
    Chunked,
}

impl FramingParser {
    fn new(max_header_bytes: usize) -> Self {
        Self {
            max_header_bytes,
            state: RequestState::Header,
            line: Vec::new(),
            header_incomplete: false,
        }
    }

    fn body_bytes_remaining(&self) -> Option<usize> {
        match self.state {
            RequestState::FixedBody(remaining) | RequestState::ChunkData(remaining) => {
                Some(usize::try_from(remaining).unwrap_or(usize::MAX))
            }
            _ => None,
        }
    }

    fn consume(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            match self.state {
                RequestState::Header => {
                    let previous_len = self.line.len();
                    self.line.extend_from_slice(bytes);
                    let search_from = previous_len.saturating_sub(3);
                    let header_end = self.line[search_from..]
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|position| search_from + position + 4);
                    if let Some(header_end) = header_end {
                        let header = &self.line[..header_end];
                        if header_end > self.max_header_bytes
                            || header.windows(2).any(|window| window == b"\n\n")
                        {
                            return Err(invalid_framing("invalid HTTP header termination"));
                        }
                        let body = validate_header(header)?;
                        self.line.clear();
                        self.header_incomplete = false;
                        self.state = match body {
                            RequestBody::None | RequestBody::Fixed(0) => RequestState::Header,
                            RequestBody::Fixed(length) => RequestState::FixedBody(length),
                            RequestBody::Chunked => RequestState::ChunkSize,
                        };
                        bytes = &bytes[header_end - previous_len..];
                    } else {
                        let lf_search_from = previous_len.saturating_sub(1);
                        if self.line.len() > self.max_header_bytes
                            || self.line[lf_search_from..]
                                .windows(2)
                                .any(|window| window == b"\n\n")
                        {
                            return Err(invalid_framing("invalid or oversized HTTP headers"));
                        }
                        self.header_incomplete = true;
                        return Ok(());
                    }
                }
                RequestState::FixedBody(remaining) => {
                    let count = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    let remaining = remaining - count as u64;
                    self.state = if remaining == 0 {
                        RequestState::Header
                    } else {
                        RequestState::FixedBody(remaining)
                    };
                    bytes = &bytes[count..];
                }
                RequestState::ChunkSize => {
                    let Some(consumed) = self.consume_line(bytes)? else {
                        return Ok(());
                    };
                    let size = parse_chunk_size(&self.line)?;
                    self.line.clear();
                    self.state = if size == 0 {
                        RequestState::Trailers
                    } else {
                        RequestState::ChunkData(size)
                    };
                    bytes = &bytes[consumed..];
                }
                RequestState::ChunkData(remaining) => {
                    let count = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    let remaining = remaining - count as u64;
                    self.state = if remaining == 0 {
                        RequestState::ChunkDataEnd
                    } else {
                        RequestState::ChunkData(remaining)
                    };
                    bytes = &bytes[count..];
                }
                RequestState::ChunkDataEnd => {
                    let count = (2 - self.line.len()).min(bytes.len());
                    self.line.extend_from_slice(&bytes[..count]);
                    bytes = &bytes[count..];
                    if !b"\r\n".starts_with(&self.line) {
                        return Err(invalid_framing("chunk data is not followed by CRLF"));
                    }
                    if self.line.len() == 2 {
                        self.line.clear();
                        self.state = RequestState::ChunkSize;
                    }
                }
                RequestState::Trailers => {
                    let Some(consumed) = self.consume_line(bytes)? else {
                        return Ok(());
                    };
                    let empty = self.line.is_empty();
                    self.line.clear();
                    if empty {
                        self.state = RequestState::Header;
                    }
                    bytes = &bytes[consumed..];
                }
            }
        }
        Ok(())
    }

    fn consume_line(&mut self, bytes: &[u8]) -> io::Result<Option<usize>> {
        let previous_len = self.line.len();
        self.line.extend_from_slice(bytes);
        if let Some(newline) = self.line[previous_len..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|position| previous_len + position)
        {
            if newline == 0 || self.line[newline - 1] != b'\r' {
                return Err(invalid_framing("bare LF in chunked framing"));
            }
            let consumed = newline + 1 - previous_len;
            self.line.truncate(newline - 1);
            Ok(Some(consumed))
        } else if self.line.len() > self.max_header_bytes {
            Err(invalid_framing("chunked framing line is too long"))
        } else {
            Ok(None)
        }
    }
}

fn validate_header(header: &[u8]) -> io::Result<RequestBody> {
    let mut content_length = None;
    let mut transfer_encoding = false;

    for line in header.split(|byte| *byte == b'\n').skip(1) {
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = line[colon + 1..]
            .strip_suffix(b"\r")
            .unwrap_or(&line[colon + 1..]);
        let value = trim_ascii(value);
        if name.eq_ignore_ascii_case(b"Content-Length") {
            if content_length.is_some() {
                return Err(invalid_framing(
                    "multiple Content-Length headers are present",
                ));
            }
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(invalid_framing("invalid Content-Length header"));
            }
            let value = std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| invalid_framing("invalid Content-Length header"))?;
            content_length = Some(value);
        } else if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
            if transfer_encoding || !value.eq_ignore_ascii_case(b"chunked") {
                return Err(invalid_framing(
                    "Transfer-Encoding must consist of exactly chunked",
                ));
            }
            transfer_encoding = true;
        }
    }

    if content_length.is_some() && transfer_encoding {
        return Err(invalid_framing(
            "both Content-Length and Transfer-Encoding are present",
        ));
    }
    Ok(if transfer_encoding {
        RequestBody::Chunked
    } else if let Some(length) = content_length {
        RequestBody::Fixed(length)
    } else {
        RequestBody::None
    })
}

fn parse_chunk_size(line: &[u8]) -> io::Result<u64> {
    let size = line.split(|byte| *byte == b';').next().unwrap();
    if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid_framing("invalid chunk size"));
    }
    std::str::from_utf8(size)
        .ok()
        .and_then(|size| u64::from_str_radix(size, 16).ok())
        .ok_or_else(|| invalid_framing("invalid chunk size"))
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn invalid_framing(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use super::*;

    struct TestIo {
        data: Vec<u8>,
        position: usize,
        chunk_size: usize,
        pending: bool,
        written: Vec<u8>,
        write_chunk_size: usize,
        pause_writes: bool,
        write_pending: bool,
        flushed: bool,
    }

    impl TestIo {
        fn new(data: &[u8], chunk_size: usize) -> Self {
            Self {
                data: data.to_vec(),
                position: 0,
                chunk_size,
                pending: false,
                written: Vec::new(),
                write_chunk_size: usize::MAX,
                pause_writes: false,
                write_pending: false,
                flushed: false,
            }
        }
    }

    impl Read for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            mut buffer: ReadBufCursor<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pending {
                self.pending = false;
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            if self.position == self.data.len() {
                return Poll::Ready(Ok(()));
            }

            let count = self
                .chunk_size
                .min(buffer.remaining())
                .min(self.data.len() - self.position);
            buffer.put_slice(&self.data[self.position..self.position + count]);
            self.position += count;
            Poll::Ready(Ok(()))
        }
    }

    impl Write for TestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.write_pending {
                self.write_pending = false;
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            if self.pause_writes {
                self.write_pending = true;
            }

            let count = self.write_chunk_size.min(buffer.len());
            self.written.extend_from_slice(&buffer[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushed = true;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn read_all(mut io: FramingGuardIo<TestIo>) -> io::Result<(Vec<u8>, TestIo)> {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut output = Vec::new();
        let mut chunk = [0; 7];

        loop {
            let mut buffer = ReadBuf::new(&mut chunk);
            match Pin::new(&mut io).poll_read(&mut context, buffer.unfilled()) {
                Poll::Pending => continue,
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(())) => {
                    if buffer.filled().is_empty() {
                        return Ok((output, io.inner));
                    }
                    output.extend_from_slice(buffer.filled());
                }
            }
        }
    }

    fn assert_rejected(io: FramingGuardIo<TestIo>) {
        let (output, inner) = read_all(io).unwrap();
        assert!(output.is_empty());
        assert_eq!(inner.written, BAD_REQUEST);
        assert!(inner.flushed);
    }

    #[test]
    fn writes_complete_rejection_for_content_length_and_transfer_encoding() {
        let request =
            b"POST / HTTP/1.1\r\ncOnTeNt-LeNgTh: 4\r\ntRaNsFeR-EnCoDiNg: chunked\r\n\r\n0\r\n\r\n";
        assert_rejected(FramingGuardIo::new(TestIo::new(request, 5), 1024));
    }

    #[test]
    fn writes_partial_rejection_for_duplicate_content_length() {
        let request = b"POST / HTTP/1.1\r\nContent-Length: 4\r\ncontent-length: 4\r\n\r\ntest";
        let mut inner = TestIo::new(request, 3);
        inner.write_chunk_size = 5;
        inner.pause_writes = true;
        assert_rejected(FramingGuardIo::new(inner, 1024));
    }

    #[test]
    fn accepts_valid_content_length_and_passes_bytes_through() {
        let request = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\ntest";
        let mut inner = TestIo::new(request, 2);
        inner.pending = true;
        let (output, inner) = read_all(FramingGuardIo::new(inner, 1024)).unwrap();
        assert_eq!(output, request);
        assert!(inner.written.is_empty());
    }

    #[test]
    fn accepts_valid_chunked_request_and_passes_bytes_through() {
        let request =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        let (output, inner) = read_all(FramingGuardIo::new(TestIo::new(request, 1), 1024)).unwrap();
        assert_eq!(output, request);
        assert!(inner.written.is_empty());
    }

    #[test]
    fn rejects_transfer_codings_other_than_exactly_chunked() {
        for value in ["gzip", "gzip, chunked", "chunked, gzip", "chunked, chunked"] {
            let request = format!("POST / HTTP/1.1\r\nTransfer-Encoding: {value}\r\n\r\n0\r\n\r\n");
            assert_rejected(FramingGuardIo::new(
                TestIo::new(request.as_bytes(), 2),
                1024,
            ));
        }

        let request = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_rejected(FramingGuardIo::new(TestIo::new(request, 3), 1024));
    }

    #[test]
    fn rejects_bare_lf_headers() {
        let request = b"GET / HTTP/1.1\nHost: example.com\n\n";
        assert_rejected(FramingGuardIo::new(TestIo::new(request, 1), 1024));
    }

    #[test]
    fn checks_second_request_after_each_body_framing() {
        let first_requests: &[&[u8]] = &[
            b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"POST /first HTTP/1.1\r\nContent-Length: 4\r\n\r\ntest",
            b"POST /first HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=value\r\ntest\r\n0\r\nTrailer: value\r\n\r\n",
        ];
        let bad = b"POST /second HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        for first in first_requests {
            let mut request = first.to_vec();
            request.extend_from_slice(bad);
            let (output, inner) =
                read_all(FramingGuardIo::new(TestIo::new(&request, 1), 1024)).unwrap();
            assert_eq!(output, *first);
            assert_eq!(inner.written, BAD_REQUEST);
            assert!(inner.flushed);
        }
    }

    #[test]
    fn passes_multiple_valid_requests_and_bodies_through() {
        let request = b"POST /first HTTP/1.1\r\nContent-Length: 4\r\n\r\ntestPOST /second HTTP/1.1\r\nTransfer-Encoding: ChUnKeD\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /third HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (output, inner) = read_all(FramingGuardIo::new(TestIo::new(request, 2), 1024)).unwrap();
        assert_eq!(output, request);
        assert!(inner.written.is_empty());
    }

    #[test]
    fn rejects_invalid_chunk_boundaries() {
        for body in [b"4\nabcd\r\n0\r\n\r\n".as_slice(), b"4\r\nabcdXX0\r\n\r\n"] {
            let mut request = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            request.extend_from_slice(body);
            let (_, inner) = read_all(FramingGuardIo::new(TestIo::new(&request, 2), 1024)).unwrap();
            assert_eq!(inner.written, BAD_REQUEST);
            assert!(inner.flushed);
        }
    }

    #[test]
    fn enforces_header_limit_without_counting_body_bytes() {
        let request = b"GET / HTTP/1.1\r\nHost: example\r\n\r\nbody";
        let header_bytes = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;

        assert_rejected(FramingGuardIo::new(
            TestIo::new(request, request.len()),
            header_bytes - 1,
        ));

        let (output, inner) = read_all(FramingGuardIo::new(
            TestIo::new(request, request.len()),
            header_bytes,
        ))
        .unwrap();
        assert_eq!(output, request);
        assert!(inner.written.is_empty());
    }
}
