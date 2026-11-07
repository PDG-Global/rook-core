use http::{Uri, uri::PathAndQuery};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid path")]
pub struct PathError;

pub fn normalize_path(path: &str) -> Result<String, PathError> {
    if !path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.contains('\\')
        || path.as_bytes().windows(2).any(|pair| pair == b"//")
    {
        return Err(PathError);
    }

    let bytes = path.as_bytes();
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            normalized.push(bytes[index]);
            index += 1;
            continue;
        }

        if index + 2 >= bytes.len() {
            return Err(PathError);
        }
        let Some(high) = hex_value(bytes[index + 1]) else {
            return Err(PathError);
        };
        let Some(low) = hex_value(bytes[index + 2]) else {
            return Err(PathError);
        };
        let byte = (high << 4) | low;
        // Encoded '/', '\\' and control bytes are rejected outright; encoded
        // ';' is rejected too, because an upstream that decodes %3B before
        // stripping path parameters would see a different path than we do
        // (raw ';' stays allowed and keeps the base-before-';' check below).
        if matches!(byte, b'/' | b'\\' | b';') || byte.is_ascii_control() {
            return Err(PathError);
        }

        if is_unreserved(byte) {
            normalized.push(byte);
        } else {
            normalized.extend_from_slice(&[b'%', HEX[high as usize], HEX[low as usize]]);
        }
        index += 3;
    }

    let normalized = String::from_utf8(normalized).map_err(|_| PathError)?;
    if normalized.split('/').any(|segment| {
        let base = segment.split_once(';').map_or(segment, |(base, _)| base);
        base == "." || base == ".."
    }) {
        return Err(PathError);
    }

    let parsed = normalized.parse::<PathAndQuery>().map_err(|_| PathError)?;
    if parsed.path() != normalized || parsed.query().is_some() {
        return Err(PathError);
    }
    Ok(normalized)
}

pub fn route_matches(prefix: &str, normalized_path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    if !prefix.starts_with('/') {
        return false;
    }
    if prefix.ends_with('/') {
        return normalized_path.starts_with(prefix);
    }

    normalized_path == prefix
        || normalized_path
            .strip_prefix(prefix)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

pub fn upstream_uri(
    base: &Uri,
    normalized_path: &str,
    query: Option<&str>,
) -> Result<Uri, PathError> {
    if base.scheme().is_none() || base.authority().is_none() || base.query().is_some() {
        return Err(PathError);
    }
    if normalize_path(normalized_path)? != normalized_path {
        return Err(PathError);
    }

    let joined = format!(
        "{}/{}",
        base.path().trim_end_matches('/'),
        normalized_path.trim_start_matches('/')
    );
    let path_and_query = match query {
        Some(query) => format!("{joined}?{query}"),
        None => joined.clone(),
    };

    let mut parts = base.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().map_err(|_| PathError)?);
    let uri = Uri::from_parts(parts).map_err(|_| PathError)?;
    if uri.scheme() != base.scheme()
        || uri.authority() != base.authority()
        || uri.path() != joined
        || uri.query() != query
    {
        return Err(PathError);
    }
    Ok(uri)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ascii_unreserved_characters() {
        assert_eq!(normalize_path("/%61dmin").unwrap(), "/admin");
        assert_eq!(
            normalize_path("/%41%5a%61%7a%30%39%2d%2e%5f%7e").unwrap(),
            "/AZaz09-._~"
        );
        assert_eq!(normalize_path("/.%77ell-known").unwrap(), "/.well-known");
    }

    #[test]
    fn canonicalizes_other_percent_escapes_without_decoding_them() {
        assert_eq!(
            normalize_path("/%3f%2b%3a%40%25%c3%a9").unwrap(),
            "/%3F%2B%3A%40%25%C3%A9"
        );
        assert_eq!(
            normalize_path("/already%20encoded").unwrap(),
            "/already%20encoded"
        );
    }

    #[test]
    fn rejects_encoded_path_separators_and_controls() {
        for path in [
            "/%2f",
            "/%2F",
            "/safe/%2fadmin",
            "/%5c",
            "/%5C",
            "/safe/%5Cadmin",
            "/%00",
            "/%0a",
            "/%1F",
            "/%7f",
        ] {
            assert!(normalize_path(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn rejects_raw_and_encoded_dot_segments() {
        for path in [
            "/.",
            "/..",
            "/./admin",
            "/../admin",
            "/safe/./admin",
            "/safe/../admin",
            "/%2e",
            "/%2E%2e",
            "/safe/%2e%2E/admin",
            "/safe/.%2e/admin",
        ] {
            assert!(normalize_path(path).is_err(), "accepted {path:?}");
        }

        for path in ["/...", "/.well-known", "/file.txt", "/safe.."] {
            assert!(normalize_path(path).is_ok(), "rejected {path:?}");
        }
    }

    #[test]
    fn rejects_dot_segments_with_semicolon_parameters() {
        for path in [
            "/public/..;/admin",
            "/.;",
            "/..;",
            "/.;param",
            "/%2e%2e;param",
            "/safe/%2e;param/admin",
        ] {
            assert!(normalize_path(path).is_err(), "accepted {path:?}");
        }

        assert_eq!(
            normalize_path("/file.txt;version=1").unwrap(),
            "/file.txt;version=1"
        );
    }

    #[test]
    fn rejects_malformed_paths_and_percent_escapes() {
        for path in [
            "",
            "admin",
            "//admin",
            "/admin//x",
            "/admin\\x",
            "/admin\n",
            "/admin\0",
            "/%",
            "/%0",
            "/%GG",
            "/%x1",
            "/admin%2",
            "/admin?query=yes",
            "/admin#fragment",
        ] {
            assert!(normalize_path(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn accepts_root_trailing_slash_and_non_ascii_path_bytes() {
        assert_eq!(normalize_path("/").unwrap(), "/");
        assert_eq!(normalize_path("/api/").unwrap(), "/api/");
        assert_eq!(normalize_path("/caf%C3%A9").unwrap(), "/caf%C3%A9");
    }

    #[test]
    fn matches_routes_only_at_segment_boundaries() {
        assert!(route_matches("/", "/anything"));
        assert!(route_matches("/api", "/api"));
        assert!(route_matches("/api", "/api/"));
        assert!(route_matches("/api", "/api/x"));
        assert!(!route_matches("/api", "/apix"));
        assert!(!route_matches("/api", "/api-v2"));
        assert!(!route_matches("/api", "/"));
        assert!(route_matches("/api/", "/api/x"));
        assert!(!route_matches("/api/", "/api"));
        assert!(!route_matches("", "/api"));
    }

    #[test]
    fn joins_base_paths_without_duplicate_slashes() {
        let cases = [
            ("https://example.com", "/api", "https://example.com/api"),
            ("https://example.com/", "/api", "https://example.com/api"),
            (
                "https://example.com/base",
                "/api",
                "https://example.com/base/api",
            ),
            (
                "https://example.com/base/",
                "/api",
                "https://example.com/base/api",
            ),
            ("https://example.com/base", "/", "https://example.com/base/"),
            (
                "https://example.com/base/",
                "/",
                "https://example.com/base/",
            ),
        ];
        for (base, path, expected) in cases {
            let base = base.parse().unwrap();
            assert_eq!(upstream_uri(&base, path, None).unwrap(), expected);
        }
    }

    #[test]
    fn preserves_scheme_authority_and_original_query() {
        let base = "https://user@example.com:8443/base".parse().unwrap();
        let uri = upstream_uri(&base, "/~user", Some("next=%2f&letter=%61&&=")).unwrap();
        assert_eq!(
            uri.to_string(),
            "https://user@example.com:8443/base/~user?next=%2f&letter=%61&&="
        );
        assert_eq!(uri.scheme_str(), Some("https"));
        assert_eq!(uri.authority().unwrap().as_str(), "user@example.com:8443");
        assert_eq!(uri.query(), Some("next=%2f&letter=%61&&="));

        let empty_query = upstream_uri(&base, "/api", Some("")).unwrap();
        assert_eq!(
            empty_query.to_string(),
            "https://user@example.com:8443/base/api?"
        );
    }

    #[test]
    fn rejects_invalid_bases_queries_and_noncanonical_paths() {
        let with_query = "https://example.com/base?old=query".parse().unwrap();
        assert!(upstream_uri(&with_query, "/api", None).is_err());

        let relative = "/base".parse().unwrap();
        assert!(upstream_uri(&relative, "/api", None).is_err());

        let base = "https://example.com/base".parse().unwrap();
        assert!(upstream_uri(&base, "/%61dmin", None).is_err());
        assert!(upstream_uri(&base, "/admin", Some("bad query")).is_err());
        assert!(upstream_uri(&base, "/admin", Some("x=#fragment")).is_err());
    }
}
