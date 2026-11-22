//! Static file serving for a site: GET/HEAD from a root directory.
//!
//! Defense in depth. The routing layer normalizes the request path
//! before dispatch (rejecting encoded separators, dot segments and
//! control bytes), and THIS module re-validates every segment, so its
//! safety does not depend on the caller. On top of the segment checks
//! the resolved path is canonicalized and required to stay under the
//! (also canonicalized) root, which closes symlink escapes.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use http_body_util::{BodyExt, Full};

/// The proxy module's response body type.
type BoxedBody = crate::proxy::ResponseBody;

/// Refuse to buffer files larger than this. GET buffers the whole body,
/// so the worst case is `max_connections` times this; the canary site is
/// under a megabyte. Streaming replaces the cap if a site ever needs
/// larger files.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// A path segment the file server will never touch, checked here rather
/// than trusted to the router: dot segments, dotfiles (`.git`, `.env`,
/// `.well-known` is answered by the ACME layer before dispatch), editor
/// leftovers (`~`, `.bak`), and any byte the router's decoding might
/// have carried through (`%`, `\`, control bytes).
fn segment_allowed(segment: &str) -> bool {
    if segment.is_empty()
        || segment.starts_with('.')
        || segment
            .bytes()
            .any(|byte| byte == b'%' || byte == b'\\' || byte.is_ascii_control())
    {
        return false;
    }
    // Case-insensitive: a tree that passed through a case-folding
    // filesystem or checkout tool must not smuggle a denied suffix past.
    let lowered = segment.to_ascii_lowercase();
    lowered != "."
        && lowered != ".."
        && !lowered.ends_with('~')
        && ![".bak", ".swp", ".orig", ".old"]
            .iter()
            .any(|suffix| lowered.ends_with(suffix))
}

fn content_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        Some("pdf") => "application/pdf",
        Some("xml") => "application/xml; charset=utf-8",
        Some("webmanifest") => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

fn response(status: StatusCode, body: Bytes) -> http::Response<BoxedBody> {
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Full::new(body).map_err(|never| match never {}).boxed())
        .expect("static response builder")
}

fn not_found() -> http::Response<BoxedBody> {
    response(StatusCode::NOT_FOUND, Bytes::from_static(b"not found\n"))
}

/// Serve `normalized_path` (a router-normalized absolute path) from
/// `root`. `root` need not be pre-canonicalized; both sides are
/// canonicalized per request, which keeps the prefix check honest even
/// if the directory is replaced by a symlink between requests.
pub async fn serve(
    root: &Path,
    method: &Method,
    normalized_path: &str,
    _request_headers: &HeaderMap,
) -> http::Response<BoxedBody> {
    if method != Method::GET && method != Method::HEAD {
        let mut denied = response(
            StatusCode::METHOD_NOT_ALLOWED,
            Bytes::from_static(b"method not allowed\n"),
        );
        denied
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return denied;
    }
    let segments: Vec<&str> = normalized_path.split('/').skip(1).collect();
    // The router guarantees a leading slash, so skip(1) yields the
    // segments; a trailing slash leaves a final empty segment, which
    // means "the directory's index".
    let (directory_hint, file_segments) = match segments.split_last() {
        Some((&"", rest)) => (true, rest.to_vec()),
        Some((last, rest)) => (false, {
            let mut all = rest.to_vec();
            all.push(last);
            all
        }),
        None => (true, Vec::new()),
    };
    if file_segments
        .iter()
        .any(|segment| !segment_allowed(segment))
    {
        return not_found();
    }
    let mut candidate = PathBuf::from(root);
    for segment in &file_segments {
        candidate.push(segment);
    }
    if directory_hint || candidate.is_dir() {
        candidate.push("index.html");
    }
    let canonical_root = match tokio::fs::canonicalize(root).await {
        Ok(root) => root,
        Err(_) => return not_found(),
    };
    let canonical = match tokio::fs::canonicalize(&candidate).await {
        Ok(canonical) => canonical,
        Err(_) => return not_found(),
    };
    if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
        return not_found();
    }
    // The REQUEST path was checked segment by segment above, but a
    // symlink inside the root can still land on a denied name
    // (`public.txt -> .env`). Re-check every canonical component below
    // the root, so the denylist holds for the file actually served.
    let Ok(relative) = canonical.strip_prefix(&canonical_root) else {
        return not_found();
    };
    if relative
        .components()
        .any(|component| !segment_allowed(&component.as_os_str().to_string_lossy()))
    {
        return not_found();
    }
    let metadata = match tokio::fs::metadata(&canonical).await {
        Ok(metadata) => metadata,
        Err(_) => return not_found(),
    };
    if metadata.len() > MAX_FILE_BYTES {
        return response(
            StatusCode::PAYLOAD_TOO_LARGE,
            Bytes::from_static(b"too large\n"),
        );
    }
    // HEAD stops after the stat: answering one must never read a byte.
    if method == Method::HEAD {
        return http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type(&canonical))
            .header(header::CONTENT_LENGTH, metadata.len().to_string())
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .header(header::CACHE_CONTROL, "public, max-age=300")
            .body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .expect("static HEAD response");
    }
    // Known, bounded TOCTOU: canonicalize-then-read is two lookups, and
    // a rename between them could move the target. The tree is
    // root-owned and read-only to rookd, so whoever could race it is
    // already root. The openat/O_NOFOLLOW form (no openat2 on FreeBSD)
    // is on the phase-2 list.
    let body = match tokio::fs::read(&canonical).await {
        Ok(body) => body,
        Err(_) => return not_found(),
    };
    http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type(&canonical))
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "public, max-age=300")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_text(response: http::Response<BoxedBody>) -> (StatusCode, String) {
        let status = response.status();
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("collect body")
            .to_bytes();
        (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("docs")).expect("docs dir");
        std::fs::write(root.join("index.html"), "<h1>home</h1>").expect("index");
        std::fs::write(root.join("style.css"), "body{}").expect("css");
        std::fs::write(root.join("docs/index.html"), "<h1>docs</h1>").expect("docs index");
        std::fs::write(root.join(".env"), "SECRET=1").expect("dotfile");
        std::fs::write(root.join("index.html.bak"), "old").expect("bak");
        std::fs::write(root.join("draft~"), "draft").expect("tilde");
        dir
    }

    #[tokio::test]
    async fn serves_index_for_root_and_directory() {
        let dir = tree();
        let (status, body) =
            body_text(serve(dir.path(), &Method::GET, "/", &HeaderMap::new()).await).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "<h1>home</h1>"));
        let (status, body) =
            body_text(serve(dir.path(), &Method::GET, "/docs/", &HeaderMap::new()).await).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "<h1>docs</h1>"));
    }

    #[tokio::test]
    async fn directory_without_index_is_not_listed() {
        let dir = tree();
        std::fs::create_dir_all(dir.path().join("empty")).expect("empty dir");
        let (status, _) =
            body_text(serve(dir.path(), &Method::GET, "/empty/", &HeaderMap::new()).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dotfiles_backups_and_tilde_files_are_refused() {
        let dir = tree();
        for path in ["/.env", "/index.html.bak", "/draft~", "/.git/config"] {
            let (status, _) =
                body_text(serve(dir.path(), &Method::GET, path, &HeaderMap::new()).await).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn hostile_segments_are_refused_at_the_file_layer() {
        // The router rejects these first; the file layer must not trust
        // that. %2e%2e / %2f / NUL / backslash reach here only if the
        // router changes, so the refusal is tested directly.
        let dir = tree();
        for path in [
            "/%2e%2e/etc/passwd",
            "/docs/%2e%2e/index.html",
            "/%2f/etc/passwd",
            "/docs\\..\\index.html",
            "/../index.html",
            "/./index.html",
        ] {
            let (status, _) =
                body_text(serve(dir.path(), &Method::GET, path, &HeaderMap::new()).await).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
        let (status, _) = body_text(
            serve(
                dir.path(),
                &Method::GET,
                "/index.html\u{0}",
                &HeaderMap::new(),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn symlink_escape_is_refused() {
        let dir = tree();
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret.txt"), "do not serve").expect("secret");
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            dir.path().join("link.txt"),
        )
        .expect("symlink");
        let (status, _) =
            body_text(serve(dir.path(), &Method::GET, "/link.txt", &HeaderMap::new()).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // A symlink that stays INSIDE the root still works.
        std::os::unix::fs::symlink(dir.path().join("style.css"), dir.path().join("inner.css"))
            .expect("inner symlink");
        let (status, body) =
            body_text(serve(dir.path(), &Method::GET, "/inner.css", &HeaderMap::new()).await).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "body{}"));
    }

    #[tokio::test]
    async fn inside_root_symlink_to_a_denied_name_is_refused() {
        // The request path is clean; the TARGET is not. The canonical
        // components below the root must pass the same denylist.
        let dir = tree();
        std::os::unix::fs::symlink(dir.path().join(".env"), dir.path().join("public.txt"))
            .expect("symlink to dotfile");
        let (status, _) =
            body_text(serve(dir.path(), &Method::GET, "/public.txt", &HeaderMap::new()).await)
                .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn denied_suffixes_are_case_insensitive() {
        let dir = tree();
        std::fs::write(dir.path().join("INDEX.HTML.BAK"), "old").expect("upper bak");
        std::fs::write(dir.path().join("x.swp"), "swap").expect("swp");
        std::fs::write(dir.path().join("y.ORIG"), "orig").expect("orig");
        std::fs::write(dir.path().join("z.old"), "old").expect("old");
        for path in ["/INDEX.HTML.BAK", "/x.swp", "/y.ORIG", "/z.old"] {
            let (status, _) =
                body_text(serve(dir.path(), &Method::GET, path, &HeaderMap::new()).await).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn head_never_reads_the_file() {
        // A stat-able but unreadable file: HEAD must answer from the
        // metadata alone, where GET fails on the read.
        let dir = tree();
        let path = dir.path().join("locked.txt");
        std::fs::write(&path, "contents").expect("locked file");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let response = serve(dir.path(), &Method::HEAD, "/locked.txt", &HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            HeaderValue::from_static("8")
        );
        let (status, _) =
            body_text(serve(dir.path(), &Method::GET, "/locked.txt", &HeaderMap::new()).await)
                .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn non_regular_files_are_refused() {
        // Pins the `canonical.is_file()` guard: without it a FIFO in
        // the tree would hang the read. `git archive` cannot emit one,
        // so this only becomes real through a refactor dropping the
        // check.
        let dir = tree();
        let fifo = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(status.success());
        // A dropped `is_file()` guard must fail fast, not hang the
        // suite (Thomas): the delayed writer below turns a guardless
        // read into junk bytes and a wrong status, and the timeout is
        // the last resort if even that stalls.
        std::thread::spawn({
            let fifo = fifo.clone();
            move || {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let _ = std::fs::write(&fifo, b"x");
            }
        });
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            serve(dir.path(), &Method::GET, "/pipe", &HeaderMap::new()),
        )
        .await
        .expect("serve answers a FIFO within 2s");
        let (status, _) = body_text(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn head_sends_headers_without_body() {
        let dir = tree();
        let response = serve(dir.path(), &Method::HEAD, "/index.html", &HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            HeaderValue::from_static("13")
        );
        let (_, body) = body_text(response).await;
        assert_eq!(body, "");
    }

    #[tokio::test]
    async fn post_is_refused() {
        let dir = tree();
        let response = serve(dir.path(), &Method::POST, "/index.html", &HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers()[header::ALLOW],
            HeaderValue::from_static("GET, HEAD")
        );
    }

    #[tokio::test]
    async fn content_types_come_from_a_closed_set() {
        let dir = tree();
        let response = serve(dir.path(), &Method::GET, "/style.css", &HeaderMap::new()).await;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            HeaderValue::from_static("text/css; charset=utf-8")
        );
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            HeaderValue::from_static("nosniff")
        );
        std::fs::write(dir.path().join("data.weird"), "x").expect("weird");
        let response = serve(dir.path(), &Method::GET, "/data.weird", &HeaderMap::new()).await;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            HeaderValue::from_static("application/octet-stream")
        );
    }
}
