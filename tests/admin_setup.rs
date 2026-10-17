mod fixtures;
mod utils;

use fixtures::{server, Error, TestServer};
use rstest::rstest;

const ADMIN_URL_SUFFIX: &str = "__dufs__/admin";
/// 配置文件在独立的 config 目录里（fixture 传 --config-dir 指到 tmpdir/config）
const CONFIG_FILE: &str = "config/admin.json";

fn setup_payload(user: &str, password: &str, scope: &str, direct: bool) -> String {
    format!(
        r#"{{"user":"{user}","password":"{password}","anonymous_scope":"{scope}","allow_direct_file_access":{direct}}}"#
    )
}

fn init_admin(server: &TestServer, scope: &str, direct: bool) -> Result<(), Error> {
    let url = format!("{}{}", server.url(), ADMIN_URL_SUFFIX);
    let resp = reqwest::blocking::Client::new()
        .put(&url)
        .header("Content-Type", "application/json")
        .body(setup_payload("admin", "pass1234", scope, direct))
        .send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

/// 首次初始化成功：写入凭据文件、生效鉴权、入口转为修改密码
#[rstest]
fn admin_setup_flow(server: TestServer) -> Result<(), Error> {
    let url = format!("{}{}", server.url(), ADMIN_URL_SUFFIX);

    // 初始化前：匿名可自由访问（空账号窗口期）
    let resp = reqwest::blocking::get(server.url().join("/test.txt")?)?;
    assert_eq!(resp.status(), 200);

    init_admin(&server, "public", false)?;

    // 配置写入独立的 config 目录，分享根里没有遗留的旧配置文件
    assert!(
        server.path().join("config").is_dir(),
        "config dir should be created"
    );
    assert!(
        !server.path().join(".dufs-admin.json").exists(),
        "legacy config file must not reappear in the share root"
    );
    // 凭据文件落盘且权限为 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(server.path().join(CONFIG_FILE))?;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
    let content = std::fs::read_to_string(server.path().join(CONFIG_FILE))?;
    assert!(content.contains("$6$"), "password should be hashed");

    // 配置文件不可通过 HTTP 读取（fixture 的 config 在服务根内，
    // 由 --config-dir 误配置的兜底防护拦截；生产布局下配置在服务根之外）
    let resp = reqwest::blocking::get(server.url().join(CONFIG_FILE)?)?;
    assert_eq!(resp.status(), 404);

    // 初始化后：匿名被拒，正确凭据可访问
    let resp = reqwest::blocking::get(server.url().join("/test.txt")?)?;
    assert_eq!(resp.status(), 401);
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/test.txt")?)
        .basic_auth("admin", Some("pass1234"))
        .send()?;
    assert_eq!(resp.status(), 200);

    // 错误凭据被拒
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/test.txt")?)
        .basic_auth("admin", Some("wrongpass"))
        .send()?;
    assert_eq!(resp.status(), 401);

    // 已初始化后匿名再调初始化接口 = 修改密码流程，未登录必须被拒
    // （匿名在访客规则外 → 401；若恰好有可写权限则进入修改密码流程 → 403）
    let resp = reqwest::blocking::Client::new()
        .put(&url)
        .header("Content-Type", "application/json")
        .body(setup_payload("evil", "evilpass", "all", true))
        .send()?;
    assert!(
        resp.status() == 401 || resp.status() == 403,
        "anonymous re-setup must be rejected, got {}",
        resp.status()
    );
    // 且管理员凭据不受影响（没有被改成 evil 账号）
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/test.txt")?)
        .basic_auth("admin", Some("pass1234"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/test.txt")?)
        .basic_auth("evil", Some("evilpass"))
        .send()?;
    assert_eq!(resp.status(), 401);

    // 管理员通过 CHECKAUTH 拿到会话 Cookie
    let resp = fetch!(b"CHECKAUTH", server.url().join("/test.txt")?)
        .basic_auth("admin", Some("pass1234"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("session cookie should be issued")
        .to_str()?
        .to_string();
    assert!(cookie.starts_with("dufs_session="));

    // 会话 Cookie 可访问
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/test.txt")?)
        .header("Cookie", &cookie)
        .send()?;
    assert_eq!(resp.status(), 200);

    Ok(())
}

/// 非法用户名（|、:、@、超长）拒绝初始化且不落盘
#[rstest]
fn admin_setup_rejects_bad_usernames(server: TestServer) -> Result<(), Error> {
    let url = format!("{}{}", server.url(), ADMIN_URL_SUFFIX);
    for user in ["a|b", "a:b", "a@b", &"x".repeat(65), "a\u{7}b"] {
        let resp = reqwest::blocking::Client::new()
            .put(&url)
            .header("Content-Type", "application/json")
            .body(setup_payload(user, "pass1234", "public", false))
            .send()?;
        assert_eq!(resp.status(), 400, "user {user:?} should be rejected");
        assert!(
            !server.path().join(CONFIG_FILE).exists(),
            "config must not be created for user {user:?}"
        );
    }
    Ok(())
}

/// 超过 4KB 的请求体被拒绝且不落盘
#[rstest]
fn admin_setup_rejects_oversized_payload(server: TestServer) -> Result<(), Error> {
    let url = format!("{}{}", server.url(), ADMIN_URL_SUFFIX);
    let big_user = "a".repeat(5000);
    let resp = reqwest::blocking::Client::new()
        .put(&url)
        .header("Content-Type", "application/json")
        .body(setup_payload(&big_user, "pass1234", "public", false))
        .send()?;
    assert_eq!(resp.status(), 400);
    assert!(!server.path().join(CONFIG_FILE).exists());
    Ok(())
}

/// MOVE/COPY 不能把任意文件改名为凭据文件（绕过初始化校验的植入路径）
#[rstest]
fn move_copy_onto_admin_config_rejected(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    // 初始化窗口期内先写入一个攻击者自选的"配置"
    let evil = r#"{"user":"evil","password":"x","anonymous_scope":"all"}"#;
    let resp = fetch!(b"PUT", server.url().join("/innocent")?)
        .body(evil.as_bytes())
        .send()?;
    assert_eq!(resp.status(), 201);

    for method in ["MOVE", "COPY"] {
        let resp = reqwest::blocking::Client::new()
            .request(
                reqwest::Method::from_bytes(method.as_bytes())?,
                server.url().join("/innocent")?,
            )
            .header("Destination", server.url().join(CONFIG_FILE)?.as_str())
            .send()?;
        assert_eq!(
            resp.status(),
            403,
            "{method} onto config file must be forbidden"
        );
    }

    // 凭据文件没有被植入
    assert!(!server.path().join(CONFIG_FILE).exists());
    let resp = reqwest::blocking::get(server.url().join(CONFIG_FILE)?)?;
    assert_eq!(resp.status(), 404);

    // 正常初始化仍然可用
    init_admin(&server, "public", false)?;
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/test.txt")?)
        .basic_auth("admin", Some("pass1234"))
        .send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

/// 畸形的 Digest 认证头不能 panic 整个进程（panic="abort" 下会杀死服务）
#[rstest]
fn malformed_digest_header_does_not_kill_server(
    #[with(&["-a", "user:pass@/"])] server: TestServer,
) -> Result<(), Error> {
    // 34 字节 nonce，多字节 UTF-8 字符跨过第 8 字节边界
    let bad_nonce = format!("{}{}{}", "0".repeat(7), "é", "A".repeat(25));
    assert_eq!(bad_nonce.len(), 34);
    for header in [
        r#"Digest a=""#,
        r#"Digest a="b"#,
        r#"Digest =,"#,
        r#"Digest username="user", nonce=""#,
        format!(r#"Digest username="user", nonce="{bad_nonce}", response="x""#).as_str(),
        r#"Digest username="user", nonce="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", response="x""#,
    ] {
        let resp = reqwest::blocking::Client::new()
            .get(server.url().join("/test.txt")?)
            .header("Authorization", header)
            .send()?;
        assert!(
            resp.status() == 401 || resp.status() == 400,
            "unexpected status {} for header {header}",
            resp.status()
        );
    }
    // 进程仍然存活，正确凭据照常工作
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/test.txt")?)
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

/// PATCH 覆盖已有内容需要删除权限：403 之后不得继续执行写入
#[rstest]
fn patch_overwrite_forbidden_without_delete(
    #[with(&["--allow-upload"])] server: TestServer,
) -> Result<(), Error> {
    let url = server.url().join("/file1")?;
    let resp = fetch!(b"PUT", url.as_str())
        .body(b"0123456789".to_vec())
        .send()?;
    assert_eq!(resp.status(), 201);

    let resp = fetch!(b"PATCH", url.as_str())
        .header("X-Update-Range", "bytes=0-4")
        .body(b"abcde".to_vec())
        .send()?;
    assert_eq!(resp.status(), 403);

    // 内容未被覆写
    let resp = reqwest::blocking::get(url.as_str())?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "0123456789");
    Ok(())
}

/// 会话 Cookie 必须过路径级权限：路径受限账号不能借 Cookie 读规则外文件
#[rstest]
fn session_cookie_respects_path_rules(
    #[with(&["-a", "user:pass@/dir1:rw"])] server: TestServer,
) -> Result<(), Error> {
    let resp = fetch!(b"CHECKAUTH", server.url().join("/dir1/test.txt")?)
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("session cookie should be issued")
        .to_str()?
        .to_string();

    // 规则外（根目录文件）→ 拒绝
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/index.html")?)
        .header("Cookie", &cookie)
        .send()?;
    assert_ne!(resp.status(), 200, "cookie must not bypass path rules");

    // 规则内（dir1）→ 允许
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/dir1/test.txt")?)
        .header("Cookie", &cookie)
        .send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

/// 匿名直链默认关闭：凭据文件里 allow_direct_file_access 缺省时不应放行
#[rstest]
fn direct_file_access_defaults_off(server: TestServer) -> Result<(), Error> {
    init_admin(&server, "public", false)?;
    let resp = reqwest::blocking::get(server.url().join("/test.txt")?)?;
    assert_eq!(
        resp.status(),
        401,
        "anonymous direct access must be off by default"
    );
    Ok(())
}

/// 经分享 token 进入的会话不能再用 ?tokengen 无限续期
#[rstest]
fn tokengen_rejected_for_share_token(server: TestServer) -> Result<(), Error> {
    init_admin(&server, "public", false)?;
    // 管理员生成一个分享 token
    let resp = reqwest::blocking::Client::new()
        .get(server.url().join("/test.txt?tokengen")?)
        .basic_auth("admin", Some("pass1234"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let token = resp.text()?;

    // 拿 token 下载 OK
    let resp = reqwest::blocking::get(server.url().join(&format!("/test.txt?token={token}"))?)?;
    assert_eq!(resp.status(), 200);

    // 但用 token 再造 token 应被拒绝
    let resp = reqwest::blocking::get(
        server
            .url()
            .join(&format!("/test.txt?token={token}&tokengen"))?,
    )?;
    assert_eq!(resp.status(), 401);
    Ok(())
}

/// 初始化为「仅公开目录」时自动创建 /public 与说明文件，访客可直接访问
#[rstest]
fn admin_setup_creates_public_dir(server: TestServer) -> Result<(), Error> {
    assert!(!server.path().join("public").exists());
    init_admin(&server, "public", false)?;

    let public_dir = server.path().join("public");
    assert!(public_dir.is_dir(), "public dir should be created on setup");
    assert!(public_dir.join("README.txt").is_file());

    // 匿名访客可浏览目录并读取说明文件（不再落到 404）
    let resp = reqwest::blocking::get(server.url().join("/public/")?)?;
    assert_eq!(resp.status(), 200);
    let resp = reqwest::blocking::get(server.url().join("/public/README.txt")?)?;
    assert_eq!(resp.status(), 200);
    let content = resp.text()?;
    assert!(content.contains("这是公开目录"));
    Ok(())
}

/// 其他访客范围（all / none）不创建公开目录
#[rstest]
fn admin_setup_other_scopes_do_not_create_public_dir(server: TestServer) -> Result<(), Error> {
    init_admin(&server, "all", false)?;
    assert!(!server.path().join("public").exists());
    Ok(())
}

/// 已存在的 public/README.txt 不会被初始化覆盖
#[rstest]
fn existing_public_readme_not_overwritten(server: TestServer) -> Result<(), Error> {
    std::fs::create_dir_all(server.path().join("public"))?;
    std::fs::write(server.path().join("public/README.txt"), "custom content")?;
    init_admin(&server, "public", false)?;
    let content = std::fs::read_to_string(server.path().join("public/README.txt"))?;
    assert_eq!(content, "custom content");
    Ok(())
}

/// 设置页把访客范围切到 public 时同样自动补建目录
#[rstest]
fn admin_settings_switch_to_public_creates_dir(server: TestServer) -> Result<(), Error> {
    init_admin(&server, "none", false)?;
    assert!(!server.path().join("public").exists());

    let resp = reqwest::blocking::Client::new()
        .put(server.url().join("/__dufs__/admin/settings")?)
        .basic_auth("admin", Some("pass1234"))
        .header("Content-Type", "application/json")
        .body(r#"{"anonymous_scope":"public","allow_direct_file_access":false}"#)
        .send()?;
    assert_eq!(resp.status(), 200);

    assert!(server.path().join("public").is_dir());
    assert!(server.path().join("public/README.txt").is_file());
    Ok(())
}

/// 匿名浏览器导航访问 ?settings：302 跳回目录页（有登录按钮）而不是空白 401
#[rstest]
fn settings_redirects_browser_navigation_to_index(server: TestServer) -> Result<(), Error> {
    init_admin(&server, "public", false)?;
    let url = server.url().join("/?settings")?;

    // 浏览器导航（Sec-Fetch-Dest: document）→ 302 回目录页
    let resp = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(url.as_str())
        .header("Sec-Fetch-Dest", "document")
        .send()?;
    assert_eq!(resp.status(), 302);
    assert_eq!(resp.headers().get("location").unwrap(), "/");

    // fetch/API 请求（无 Sec-Fetch 头）→ 仍然 401，供前端识别未登录
    let resp = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(url.as_str())
        .send()?;
    assert_eq!(resp.status(), 401);

    // 管理员访问 ?settings → 正常渲染设置页
    let resp = reqwest::blocking::Client::new()
        .get(url.as_str())
        .basic_auth("admin", Some("pass1234"))
        .send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

/// zip 打包保留空目录
#[rstest]
fn zip_includes_empty_dirs(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    std::fs::create_dir_all(server.path().join("dir1/empty-inside"))?;
    let resp = reqwest::blocking::get(server.url().join("/dir1/?zip")?)?;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes()?.to_vec();
    // zip 的条目名以明文存储在本地文件头里，按字节检索即可
    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
    assert!(
        bytes_contain(&body, b"empty-inside/"),
        "empty dir entry missing in zip"
    );
    assert!(
        bytes_contain(&body, b"test.txt"),
        "file entry missing in zip"
    );
    Ok(())
}
