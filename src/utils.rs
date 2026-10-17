use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
#[cfg(feature = "tls")]
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    borrow::Cow,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// 单个请求允许的 Range 数量上限。
///
/// 多段 Range 响应需要从磁盘逐段读取，无上限的 range 列表会让客户端用一个
/// 小请求放大成大量磁盘工作（旧实现还会进内存）。
const MAX_RANGES: usize = 32;

pub fn unix_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

pub fn encode_uri(v: &str) -> String {
    let parts: Vec<_> = v.split('/').map(urlencoding::encode).collect();
    parts.join("/")
}

pub fn decode_uri(v: &str) -> Option<Cow<'_, str>> {
    percent_encoding::percent_decode(v.as_bytes())
        .decode_utf8()
        .ok()
}

pub fn get_file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
}

#[cfg(unix)]
pub async fn get_file_mtime_and_mode(path: &Path) -> Result<(DateTime<Utc>, u16)> {
    use std::os::unix::prelude::MetadataExt;
    let meta = tokio::fs::metadata(path).await?;
    let datetime: DateTime<Utc> = meta.modified()?.into();
    Ok((datetime, meta.mode() as u16))
}

#[cfg(not(unix))]
pub async fn get_file_mtime_and_mode(path: &Path) -> Result<(DateTime<Utc>, u16)> {
    let meta = tokio::fs::metadata(&path).await?;
    let datetime: DateTime<Utc> = meta.modified()?.into();
    Ok((datetime, 0o644))
}

pub fn try_get_file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("Failed to get file name of `{}`", path.display()))
}

pub fn glob(pattern: &str, target: &str) -> bool {
    let pat = match ::glob::Pattern::new(pattern) {
        Ok(pat) => pat,
        Err(_) => return false,
    };
    pat.matches(target)
}

/// 在 `base` 下拼接 `relative`，拒绝任何越出 `base` 的成分（绝对路径、`..` 等）。
pub fn join_within(base: &Path, relative: &str) -> Option<PathBuf> {
    if Path::new(relative)
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return None;
    }
    let path = base.join(relative);
    path.starts_with(base).then_some(path)
}

// Load public certificate from file.
#[cfg(feature = "tls")]
pub fn load_certs<T: AsRef<Path>>(file_name: T) -> Result<Vec<CertificateDer<'static>>> {
    let mut certs = vec![];
    for cert in CertificateDer::pem_file_iter(file_name.as_ref()).with_context(|| {
        format!(
            "Failed to load cert file at `{}`",
            file_name.as_ref().display()
        )
    })? {
        let cert = cert.with_context(|| {
            format!(
                "Invalid certificate data in file `{}`",
                file_name.as_ref().display()
            )
        })?;
        certs.push(cert)
    }
    if certs.is_empty() {
        anyhow::bail!(
            "No supported certificate in file `{}`",
            file_name.as_ref().display()
        );
    }
    Ok(certs)
}

// Load private key from file.
#[cfg(feature = "tls")]
pub fn load_private_key<T: AsRef<Path>>(file_name: T) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(file_name.as_ref()).with_context(|| {
        format!(
            "Failed to load key file at `{}`",
            file_name.as_ref().display()
        )
    })
}

pub fn parse_range(range: &str, size: u64) -> Option<Vec<(u64, u64)>> {
    let (unit, ranges) = range.split_once('=')?;
    if unit != "bytes" {
        return None;
    }

    let mut result: Vec<(u64, u64)> = Vec::new();
    for range in ranges.split(',') {
        let (start, end) = range.trim().split_once('-')?;
        let item = if start.is_empty() {
            let offset = end.parse::<u64>().ok()?;
            // 长度为 0 的后缀 range 无法满足；且空文件下 `size - 1` 会下溢。
            if offset == 0 || offset > size {
                return None;
            }
            (size - offset, size - 1)
        } else {
            let start = start.parse::<u64>().ok()?;
            if start >= size {
                return None;
            }
            if end.is_empty() {
                (start, size - 1)
            } else {
                let end = end.parse::<u64>().ok()?;
                if start > end {
                    return None;
                }
                // RFC 9110 §14.1.2：last-pos 超出文件末尾时截断到 size - 1
                (start, end.min(size - 1))
            }
        };
        // 忽略重复 range，防止被用来放大工作量。
        if !result.contains(&item) {
            result.push(item);
        }
        if result.len() > MAX_RANGES {
            return None;
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_key() {
        assert!(glob("", ""));
        assert!(glob(".*", ".git"));
        assert!(glob("abc", "abc"));
        assert!(glob("a*c", "abc"));
        assert!(glob("a?c", "abc"));
        assert!(glob("a*c", "abbc"));
        assert!(glob("*c", "abc"));
        assert!(glob("a*", "abc"));
        assert!(glob("?c", "bc"));
        assert!(glob("a?", "ab"));
        assert!(!glob("abc", "adc"));
        assert!(!glob("abc", "abcd"));
        assert!(!glob("a?c", "abbc"));
        assert!(!glob("*.log", "log"));
        assert!(glob("*.abc-cba", "xyz.abc-cba"));
        assert!(glob("*.abc-cba", "123.xyz.abc-cba"));
        assert!(glob("*.log", ".log"));
        assert!(glob("*.log", "a.log"));
        assert!(glob("*/", "abc/"));
        assert!(!glob("*/", "abc"));
    }

    #[test]
    fn test_join_within() {
        let base = if cfg!(windows) {
            Path::new(r"C:\srv\assets")
        } else {
            Path::new("/srv/assets")
        };
        assert_eq!(join_within(base, "index.js"), Some(base.join("index.js")));
        assert_eq!(
            join_within(base, "css/index.css"),
            Some(base.join("css/index.css"))
        );
        // `Path::join` 会把这类操作数当作替换 base 处理，必须拒绝
        let escape = if cfg!(windows) {
            "C:secret"
        } else {
            "/etc/passwd"
        };
        assert_eq!(join_within(base, escape), None);
        // `starts_with` 是词法比较，`..` 必须显式拒绝
        assert_eq!(join_within(base, ".."), None);
        assert_eq!(join_within(base, "a/../secret"), None);
        assert_eq!(join_within(base, "a/../../secret"), None);
    }

    #[test]
    fn test_parse_range() {
        assert_eq!(parse_range("bytes=0-499", 500), Some(vec![(0, 499)]));
        assert_eq!(parse_range("bytes=0-", 500), Some(vec![(0, 499)]));
        assert_eq!(parse_range("bytes=299-", 500), Some(vec![(299, 499)]));
        assert_eq!(parse_range("bytes=-500", 500), Some(vec![(0, 499)]));
        assert_eq!(parse_range("bytes=-300", 500), Some(vec![(200, 499)]));
        assert_eq!(
            parse_range("bytes=0-199, 100-399, 400-, -200", 500),
            Some(vec![(0, 199), (100, 399), (400, 499), (300, 499)])
        );
        // RFC 9110 §14.1.2：last-pos >= size 时截断到 size - 1
        assert_eq!(parse_range("bytes=0-500", 500), Some(vec![(0, 499)]));
        assert_eq!(parse_range("bytes=0-999", 500), Some(vec![(0, 499)]));
        assert_eq!(parse_range("bytes=300-999", 500), Some(vec![(300, 499)]));
        assert_eq!(
            parse_range("bytes=0-199, 300-999", 500),
            Some(vec![(0, 199), (300, 499)])
        );
        // issue #735：5 字节文件
        assert_eq!(parse_range("bytes=0-5", 5), Some(vec![(0, 4)]));
        assert_eq!(parse_range("bytes=0-9", 5), Some(vec![(0, 4)]));
        assert_eq!(parse_range("bytes=5-", 5), None);
        assert_eq!(parse_range("bytes=-501", 500), None);
        assert_eq!(parse_range("bytes=0-199,", 500), None);
        assert_eq!(parse_range("bytes=0-199, 500-", 500), None);
        // 长度为 0 的后缀 range 无法满足且不能下溢
        assert_eq!(parse_range("bytes=-0", 500), None);
        assert_eq!(parse_range("bytes=-0", 0), None);
        assert_eq!(parse_range("bytes=0-", 0), None);
        assert_eq!(parse_range("bytes=0-0", 0), None);
        // 重复 range 被忽略
        assert_eq!(parse_range("bytes=0-9, 0-9, 0-9", 500), Some(vec![(0, 9)]));
        // 超量 range 整体拒绝，限定单个请求的工作量
        let too_many = (0..MAX_RANGES + 1)
            .map(|i| format!("{}-{}", i * 2, i * 2 + 1))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(parse_range(&format!("bytes={too_many}"), 1000), None);
    }
}
