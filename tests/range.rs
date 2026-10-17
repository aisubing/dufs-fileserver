mod fixtures;
mod utils;

use fixtures::{server, Error, TestServer};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rstest::rstest;

#[rstest]
fn get_file_range(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-6"))
        .send()?;
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes 0-6/18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    assert_eq!(resp.headers().get("content-length").unwrap(), "7");
    assert_eq!(resp.text()?, "This is");
    Ok(())
}

#[rstest]
fn get_file_range_beyond(server: TestServer) -> Result<(), Error> {
    // last-pos 超出文件末尾时截断到 size - 1（RFC 9110 §14.1.2）
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=12-20"))
        .send()?;
    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 12-17/18"
    );
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    assert_eq!(resp.headers().get("content-length").unwrap(), "6");
    assert_eq!(resp.text()?, "x.html");
    Ok(())
}

#[rstest]
fn get_file_range_invalid(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=20-"))
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    Ok(())
}

fn parse_multipart_body<'a>(body: &'a str, boundary: &str) -> Vec<(HeaderMap, &'a str)> {
    body.split(&format!("--{boundary}"))
        .filter(|part| !part.is_empty() && *part != "--\r\n")
        .map(|part| {
            let (head, body) = part.trim_ascii().split_once("\r\n\r\n").unwrap();
            let headers = head
                .split("\r\n")
                .fold(HeaderMap::new(), |mut headers, header| {
                    let (key, value) = header.split_once(":").unwrap();
                    let key = HeaderName::from_bytes(key.as_bytes()).unwrap();
                    let value = HeaderValue::from_str(value.trim_ascii_start()).unwrap();
                    headers.insert(key, value);
                    headers
                });
            (headers, body)
        })
        .collect()
}

#[rstest]
fn get_file_multipart_range(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-11, 6-17"))
        .send()?;
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()?
        .to_string();
    assert!(content_type.starts_with("multipart/byteranges; boundary="));

    let boundary = content_type.split_once('=').unwrap().1.trim_ascii_start();
    assert!(!boundary.is_empty());

    let body = resp.text()?;
    let parts = parse_multipart_body(&body, boundary);
    assert_eq!(parts.len(), 2);

    let (headers, body) = &parts[0];
    assert_eq!(headers.get("content-range").unwrap(), "bytes 0-11/18");
    assert_eq!(*body, "This is inde");

    let (headers, body) = &parts[1];
    assert_eq!(headers.get("content-range").unwrap(), "bytes 6-17/18");
    assert_eq!(*body, "s index.html");

    Ok(())
}

#[rstest]
fn get_file_range_suffix_zero(server: TestServer) -> Result<(), Error> {
    // 长度为 0 的后缀 range 无法满足（旧实现还会下溢 panic）
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=-0"))
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    Ok(())
}

#[rstest]
fn get_file_multipart_range_too_many(server: TestServer) -> Result<(), Error> {
    // 超过 32 个 range 会让客户端用一个小请求放大磁盘工作量
    let ranges = (0..18)
        .map(|end| format!("0-{end}"))
        .chain((0..16).map(|end| format!("1-{end}")))
        .collect::<Vec<_>>()
        .join(",");
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", format!("bytes={ranges}"))
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    Ok(())
}

#[rstest]
fn head_file_multipart_range(server: TestServer) -> Result<(), Error> {
    // HEAD 必须报告与 GET 相同的头，但不传输响应体
    let get = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-11, 6-17"))
        .send()?;
    assert_eq!(get.status(), 206);
    let content_type = get
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()?
        .to_string();
    assert!(content_type.starts_with("multipart/byteranges; boundary="));
    let body_len = get.text()?.len();

    let resp = fetch!(b"HEAD", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-11, 6-17"))
        .send()?;
    assert_eq!(resp.status(), 206);
    let head_content_type = resp.headers().get("content-type").unwrap().to_str()?;
    assert!(head_content_type.starts_with("multipart/byteranges; boundary="));
    assert_eq!(
        resp.headers().get("content-length").unwrap(),
        &body_len.to_string()
    );
    assert_eq!(resp.text()?, "");
    Ok(())
}

#[rstest]
fn get_file_multipart_range_large(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    // 超过读取缓冲区的 range 必须完整地流式返回
    let data: String = (0..200_000u32)
        .map(|i| (b'a' + (i % 26) as u8) as char)
        .collect();
    let url = format!("{}big.txt", server.url());
    let resp = fetch!(b"PUT", &url).body(data.clone()).send()?;
    assert_eq!(resp.status(), 201);

    let resp = fetch!(b"GET", &url)
        .header(
            "range",
            HeaderValue::from_static("bytes=0-149999, 100000-199999"),
        )
        .send()?;
    assert_eq!(resp.status(), 206);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()?
        .to_string();
    let boundary = content_type.split_once('=').unwrap().1.trim_ascii_start();
    let body = resp.text()?;
    let parts = parse_multipart_body(&body, boundary);
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].1, &data[0..150_000]);
    assert_eq!(parts[1].1, &data[100_000..200_000]);
    Ok(())
}

#[rstest]
fn get_file_multipart_range_invalid(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-6, 20-30"))
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    assert_eq!(resp.headers().get("content-length").unwrap(), "0");
    Ok(())
}

#[rstest]
fn get_file_range_reversed(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=10-1"))
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    Ok(())
}

#[rstest]
fn get_file_multipart_range_reversed(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=10-1,20-2"))
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    Ok(())
}
