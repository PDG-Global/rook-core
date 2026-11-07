#![forbid(unsafe_code)]

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use clap::Parser;
use hyper::rt::{Read, ReadBuf, ReadBufCursor, Write};
use rookd::framing::FramingGuardIo;

const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_MUTATIONS: usize = 32;

const CORPUS: &[&[u8]] = &[
    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"POST /fixed HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest",
    b"POST /fake-fixed HTTP/1.1\r\nHost: example.com\r\nContent-Length: 71\r\n\r\nGET /not-a-request HTTP/1.1\r\nHost: attacker.example\r\nContent-Length: 0\r\n\r\n",
    b"POST /chunked HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=value\r\ntest\r\n0\r\nTrailer: value\r\n\r\n",
    b"POST /fake-chunked HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n47\r\nPOST /not-a-request HTTP/1.1\r\nHost: attacker.example\r\nContent-Length: 0\r\n\r\n\r\n0\r\nX-Trailer: still-a-body\r\n\r\n",
    b"POST /cl-te HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    b"POST /duplicate-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
    b"POST /conflicting-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc",
    b"POST /invalid-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3x\r\n\r\nabc",
    b"POST /overflow-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: 18446744073709551616\r\n\r\n",
    b"POST /te-name HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
    b"POST /te-value HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
    b"POST /te-repeat HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    b"GET /bare-lf HTTP/1.1\nHost: example.com\n\n",
    b"POST /chunk-lf HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\ntest\r\n0\r\n\r\n",
    b"POST /chunk-end HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntestXX0\r\n\r\n",
    b"POST /chunk-size HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\ntest\r\n0\r\n\r\n",
    b"POST /chunk-overflow HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\n",
    b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\nPOST /second HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    b"POST /first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntestPOST /second HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
    b"POST /first HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nTrailer: value\r\n\r\nGET /second HTTP/1.1\nHost: example.com\n\n",
    b"POST /first HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n",
];

const MUTATION_TOKENS: &[&[u8]] = &[
    b"\r",
    b"\n",
    b"\r\n",
    b"\r\n\r\n",
    b"Content-Length: 0\r\n",
    b"Content-Length: 3\r\n",
    b"Transfer-Encoding: chunked\r\n",
    b"Transfer-Encoding: gzip, chunked\r\n",
    b"0\r\n\r\n",
    b"4\r\ntest\r\n",
    b"Trailer: value\r\n",
    b"GET /fake HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
];

#[derive(Debug, Parser)]
#[command(
    name = "framing-fuzz",
    about = "Bounded deterministic fuzzing for FramingGuardIo"
)]
struct Cli {
    #[arg(long, default_value_t = 60)]
    duration_seconds: u64,

    #[arg(long, default_value_t = 250_000)]
    max_iterations: u64,

    #[arg(long, default_value_t = 0x4d59_5df4_d0f3_3173)]
    seed: u64,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn index(&mut self, upper: usize) -> usize {
        (self.next() % upper as u64) as usize
    }

    fn range(&mut self, range: std::ops::RangeInclusive<usize>) -> usize {
        let start = *range.start();
        start + self.index(range.end() - start + 1)
    }
}

struct MemoryIo {
    data: Vec<u8>,
    position: usize,
    read_chunk: usize,
    read_pending_every: usize,
    reads: usize,
    written: Vec<u8>,
    write_chunk: usize,
    write_pending_every: usize,
    writes: usize,
    flushed: bool,
}

impl MemoryIo {
    fn new(data: &[u8], rng: &mut Rng) -> Self {
        Self {
            data: data.to_vec(),
            position: 0,
            read_chunk: rng.range(1..=97),
            read_pending_every: rng.index(5),
            reads: 0,
            written: Vec::new(),
            write_chunk: rng.range(1..=BAD_REQUEST.len()),
            write_pending_every: rng.index(4),
            writes: 0,
            flushed: false,
        }
    }
}

impl Read for MemoryIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut buffer: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        if self.read_pending_every > 0 && self.reads.is_multiple_of(self.read_pending_every) {
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.position == self.data.len() {
            return Poll::Ready(Ok(()));
        }
        let count = self
            .read_chunk
            .min(buffer.remaining())
            .min(self.data.len() - self.position);
        buffer.put_slice(&self.data[self.position..self.position + count]);
        self.position += count;
        Poll::Ready(Ok(()))
    }
}

impl Write for MemoryIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        if self.write_pending_every > 0 && self.writes.is_multiple_of(self.write_pending_every) {
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        let count = self.write_chunk.min(buffer.len());
        self.written.extend_from_slice(&buffer[..count]);
        assert!(self.written.len() <= BAD_REQUEST.len());
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

#[derive(Clone, Copy)]
enum CaseKind {
    Seed,
    Random,
    Truncated,
    Mutated,
    Spliced,
}

impl CaseKind {
    const ALL: [Self; 5] = [
        Self::Seed,
        Self::Random,
        Self::Truncated,
        Self::Mutated,
        Self::Spliced,
    ];

    fn index(self) -> usize {
        match self {
            Self::Seed => 0,
            Self::Random => 1,
            Self::Truncated => 2,
            Self::Mutated => 3,
            Self::Spliced => 4,
        }
    }
}

fn seed(index: usize) -> Vec<u8> {
    CORPUS[index % CORPUS.len()].to_vec()
}

fn random_bytes(rng: &mut Rng) -> Vec<u8> {
    let length = rng.range(0..=2048);
    (0..length)
        .map(|_| {
            if rng.index(3) == 0 {
                let token = MUTATION_TOKENS[rng.index(MUTATION_TOKENS.len())];
                token[rng.index(token.len())]
            } else {
                rng.next() as u8
            }
        })
        .collect()
}

fn mutate(input: &mut Vec<u8>, rng: &mut Rng) {
    for _ in 0..rng.range(1..=MAX_MUTATIONS) {
        match rng.index(5) {
            0 if !input.is_empty() => {
                let position = rng.index(input.len());
                input[position] = rng.next() as u8;
            }
            1 => {
                let token = MUTATION_TOKENS[rng.index(MUTATION_TOKENS.len())];
                let position = rng.range(0..=input.len());
                let available = MAX_INPUT_BYTES - input.len();
                let count = token.len().min(available);
                input.splice(position..position, token[..count].iter().copied());
            }
            2 if !input.is_empty() => {
                let start = rng.index(input.len());
                let end = rng.range(start..=input.len());
                input.drain(start..end);
            }
            3 if !input.is_empty() => {
                let start = rng.index(input.len());
                let end = rng.range(start..=input.len());
                let count = (end - start).min(MAX_INPUT_BYTES - input.len());
                let copied = input[start..start + count].to_vec();
                input.splice(end..end, copied);
            }
            _ => {
                if !input.is_empty() {
                    input.truncate(rng.index(input.len()));
                }
            }
        }
    }
}

fn make_case(iteration: u64, rng: &mut Rng) -> (Vec<u8>, CaseKind) {
    let kind = if iteration < CORPUS.len() as u64 {
        CaseKind::Seed
    } else {
        CaseKind::ALL[rng.index(CaseKind::ALL.len())]
    };
    let mut input = match kind {
        CaseKind::Seed => seed(iteration as usize),
        CaseKind::Random => random_bytes(rng),
        CaseKind::Truncated => {
            let mut input = seed(rng.index(CORPUS.len()));
            input.truncate(rng.range(0..=input.len()));
            input
        }
        CaseKind::Mutated => {
            let mut input = seed(rng.index(CORPUS.len()));
            mutate(&mut input, rng);
            input
        }
        CaseKind::Spliced => {
            let first = seed(rng.index(CORPUS.len()));
            let second = seed(rng.index(CORPUS.len()));
            let first_cut = rng.range(0..=first.len());
            let second_cut = rng.range(0..=second.len());
            let mut input = first[..first_cut].to_vec();
            let count = second_cut.min(MAX_INPUT_BYTES - input.len());
            input.extend_from_slice(&second[..count]);
            if rng.index(2) == 0 {
                mutate(&mut input, rng);
            }
            input
        }
    };
    input.truncate(MAX_INPUT_BYTES);
    (input, kind)
}

fn run_case(input: &[u8], rng: &mut Rng) -> bool {
    let inner = MemoryIo::new(input, rng);
    let max_header_bytes = rng.range(32..=2048);
    let mut io = FramingGuardIo::new(inner, max_header_bytes);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut output = Vec::new();
    let mut buffer = [0; 131];
    let max_polls = 4096 + input.len() * 16;

    for _ in 0..max_polls {
        let read_size = rng.range(1..=buffer.len());
        let mut read_buffer = ReadBuf::new(&mut buffer[..read_size]);
        match Pin::new(&mut io).poll_read(&mut context, read_buffer.unfilled()) {
            Poll::Pending => continue,
            Poll::Ready(Err(error)) => panic!("direct framing read failed: {error}"),
            Poll::Ready(Ok(())) => {
                if read_buffer.filled().is_empty() {
                    let inner = io.into_inner();
                    assert!(output.len() <= input.len());
                    assert_eq!(output, input[..output.len()]);
                    assert!(inner.written.is_empty() || inner.written == BAD_REQUEST);
                    assert_eq!(inner.flushed, !inner.written.is_empty());
                    return !inner.written.is_empty();
                }
                output.extend_from_slice(read_buffer.filled());
                assert!(output.len() <= input.len());
                assert_eq!(output, input[..output.len()]);
            }
        }
    }
    panic!(
        "poll budget exhausted (input bytes={}, read chunk={}, read pending every={})",
        input.len(),
        io.inner().read_chunk,
        io.inner().read_pending_every
    );
}

fn main() {
    let cli = Cli::parse();
    assert!(cli.duration_seconds > 0, "duration must be nonzero");
    assert!(cli.max_iterations > 0, "iteration limit must be nonzero");
    let started = Instant::now();
    let duration = Duration::from_secs(cli.duration_seconds);
    let mut rng = Rng(cli.seed);
    let mut cases = [0u64; CaseKind::ALL.len()];
    let mut rejected = 0u64;
    let mut iterations = 0u64;

    while iterations < cli.max_iterations && started.elapsed() < duration {
        let (input, kind) = make_case(iterations, &mut rng);
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_case(&input, &mut rng)));
        match result {
            Ok(was_rejected) => {
                rejected += u64::from(was_rejected);
                cases[kind.index()] += 1;
            }
            Err(payload) => {
                eprintln!(
                    "failure: seed={} iteration={} kind={} input={:?}",
                    cli.seed,
                    iterations,
                    kind.index(),
                    input
                );
                std::panic::resume_unwind(payload);
            }
        }
        iterations += 1;
    }

    println!(
        "framing-fuzz: seed={} iterations={} elapsed={:.3}s rejected={} passed={} cases(seed/random/truncated/mutated/spliced)={:?}",
        cli.seed,
        iterations,
        started.elapsed().as_secs_f64(),
        rejected,
        iterations - rejected,
        cases
    );
}
