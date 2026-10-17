#![allow(clippy::too_many_arguments)]

use crate::auth::{www_authenticate, AccessControl, AccessPaths, AccessPerm};
use crate::http_utils::{body_full, IncomingStream, LengthLimitedStream};
use crate::noscript::{detect_noscript, generate_noscript_html};
use crate::utils::{
    decode_uri, encode_uri, get_file_mtime_and_mode, get_file_name, glob, join_within, parse_range,
    try_get_file_name,
};
use crate::Args;

use anyhow::{anyhow, bail, Result};
use async_zip::{tokio::write::ZipFileWriter, Compression, ZipDateTime, ZipEntryBuilder};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use chrono::{LocalResult, TimeZone, Utc};
use futures_util::{pin_mut, TryStreamExt};
use headers::{
    AcceptRanges, AccessControlAllowOrigin, CacheControl, ContentLength, ContentType, ETag,
    HeaderMap, HeaderMapExt, IfMatch, IfModifiedSince, IfNoneMatch, IfRange, IfUnmodifiedSince,
    LastModified, Range,
};
use http_body_util::{combinators::BoxBody, BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::{
    body::Incoming,
    header::{
        HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE,
        CONTENT_TYPE, RANGE,
    },
    Method, StatusCode, Uri,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha_crypt::{PasswordHasher, ShaCrypt};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::Metadata;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf, MAIN_SEPARATOR};
use std::sync::atomic::{self, AtomicBool};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite};
use tokio::{fs, io};

use tokio_util::compat::FuturesAsyncWriteCompatExt;
use tokio_util::io::{ReaderStream, StreamReader};
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};
use xml::escape::escape_str_pcdata;

pub type Request = hyper::Request<Incoming>;
pub type Response = hyper::Response<BoxBody<Bytes, anyhow::Error>>;

const INDEX_HTML: &str = include_str!("../assets/index.html");
const INDEX_CSS: &str = include_str!("../assets/index.css");
const INDEX_JS: &str = include_str!("../assets/index.js");
const FAVICON_ICO: &[u8] = include_bytes!("../assets/favicon.ico");
const INDEX_NAME: &str = "index.html";
const BUF_SIZE: usize = 65536;
const EDITABLE_TEXT_MAX_SIZE: u64 = 4194304; // 4M
const RESUMABLE_UPLOAD_MIN_SIZE: u64 = 20971520; // 20M
const HEALTH_CHECK_PATH: &str = "__dufs__/health";
const ADMIN_SETUP_PATH: &str = "__dufs__/admin";
const ADMIN_SETTINGS_PATH: &str = "__dufs__/admin/settings";
const SESSION_COOKIE_NAME: &str = "dufs_session";
/// 访客公开目录名（与匿名规则 @/public 保持一致）
const PUBLIC_DIR_NAME: &str = "public";
/// 管理员配置文件名（位于配置目录内，与分享的文件完全分开）
const ADMIN_CONFIG_FILE: &str = "admin.json";
pub const MAX_SUBPATHS_COUNT: u64 = 1000;

/// 管理员配置目录。
///
/// 优先使用 `--config-dir` 显式指定（Docker 镜像固定传 /data/config）；
/// 未指定时默认 `~/.config/dufs`，保证配置永远不会落在被分享的目录里，
/// 也不会与用户的文件同名冲突。
fn admin_config_dir(args: &Args) -> PathBuf {
    if let Some(dir) = &args.config_dir {
        return dir.clone();
    }
    if let Some(home) = home_dir() {
        return home.join(".config").join("dufs");
    }
    // 兜底：没有 HOME 时放到服务目录的旁边（同样不在服务根内）
    args.serve_path
        .parent()
        .unwrap_or(&args.serve_path)
        .join("config")
}

fn admin_config_path(args: &Args) -> PathBuf {
    admin_config_dir(args).join(ADMIN_CONFIG_FILE)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// 相对路径是否落在受保护的配置目录内。
///
/// 正常布局下配置目录在服务根之外，此判断永远为 false；
/// 保留它作为 --config-dir 误指到服务根内时的兜底防护。
fn is_protected_config_path(args: &Args, relative_path: &str) -> bool {
    let Some(config_dir) = &args.config_dir else {
        return false;
    };
    let Ok(served) = config_dir.strip_prefix(&args.serve_path) else {
        return false;
    };
    let served = normalize_path(served);
    served == relative_path || relative_path.starts_with(&format!("{served}/"))
}

/// 首次初始化后保存到数据目录的管理员配置
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminConfig {
    user: String,
    password: String,
    #[serde(default = "default_true")]
    allow_anonymous_read: bool,
    /// 访客免登录可见范围：all（全站只读）| public（仅 /public）| none（必须登录）
    #[serde(default)]
    anonymous_scope: Option<String>,
    /// 是否允许匿名通过完整链接直接访问具体文件（仅「仅公开目录」模式生效）
    #[serde(default = "default_true")]
    allow_direct_file_access: bool,
}

#[derive(Debug, Deserialize)]
struct AdminSettingsPayload {
    anonymous_scope: String,
    #[serde(default)]
    allow_direct_file_access: Option<bool>,
}

/// 访客可见范围 -> 鉴权规则
fn build_auth_rules(user: &str, hashed_password: &str, anonymous_scope: &str) -> Vec<String> {
    let mut rules = vec![format!("{user}:{hashed_password}@/:rw")];
    match anonymous_scope {
        "all" => rules.push("@/".to_string()),
        "public" => rules.push("@/public".to_string()),
        _ => {}
    }
    rules
}

/// 兼容旧配置：没有 anonymous_scope 时按 allow_anonymous_read 推导
fn resolve_anonymous_scope(config: &AdminConfig) -> String {
    match config.anonymous_scope.as_deref() {
        Some(scope) if !scope.is_empty() => scope.to_string(),
        _ if config.allow_anonymous_read => "all".to_string(),
        _ => "none".to_string(),
    }
}

/// 访客公开目录的说明文件内容（与前端「一键创建公开目录」保持一致）
const PUBLIC_DIR_README: &str = "\
这是公开目录
============

· 访客无需登录即可浏览和下载本目录里的文件
· 请把需要分享给他人的文件放到这里
· 其他目录只有管理员登录后才能访问

（本说明由 Dufs 自动创建，可以自由修改或删除）
";

#[derive(Debug, Deserialize)]
struct AdminPasswordPayload {
    password: String,
}

#[derive(Debug, Deserialize)]
struct AdminSetupPayload {
    user: String,
    password: String,
    #[serde(default = "default_true")]
    allow_anonymous_read: bool,
    #[serde(default)]
    anonymous_scope: Option<String>,
    #[serde(default)]
    allow_direct_file_access: Option<bool>,
}

fn default_true() -> bool {
    true
}

pub struct Server {
    args: Args,
    assets_prefix: String,
    html: Cow<'static, str>,
    single_file_req_paths: Vec<String>,
    running: Arc<AtomicBool>,
    auth: Arc<RwLock<AccessControl>>,
    /// 运行时开关：是否允许匿名直链读取具体文件
    direct_file_access: Arc<AtomicBool>,
    /// 管理员配置的内存缓存：启动时从数据目录加载，变更后同步更新，
    /// 避免每个列表请求都同步读盘
    admin_config: RwLock<Option<AdminConfig>>,
}

impl Server {
    pub fn init(mut args: Args, running: Arc<AtomicBool>) -> Result<Self> {
        Self::load_admin_credentials(&mut args)?;
        // 分享根可能还不存在（如新布局首次启动的 /data/files），自动创建，
        // 避免首访出现整站 404
        if !args.path_is_file {
            if let Err(err) = std::fs::create_dir_all(&args.serve_path) {
                log::warn!(
                    "failed to create serve path {}: {err}",
                    args.serve_path.display()
                );
            }
        }
        let admin_config = Self::load_admin_config_sync(&admin_config_path(&args));
        let auth = Arc::new(RwLock::new(args.auth.clone()));
        let direct_file_access = Arc::new(AtomicBool::new(
            admin_config
                .as_ref()
                .map(|config| config.allow_direct_file_access)
                .unwrap_or(false),
        ));
        // 前端资源前缀带构建编号：每次构建都会变化，浏览器自动重新下载，
        // 从而避免"改了前端但用户还在用旧缓存"的问题
        let build_id = option_env!("DUFS_BUILD_ID")
            .filter(|value| !value.is_empty())
            .unwrap_or(env!("CARGO_PKG_VERSION"));
        let assets_prefix = format!("__dufs_v{build_id}__/");
        let single_file_req_paths = if args.path_is_file {
            vec![
                args.uri_prefix.to_string(),
                args.uri_prefix
                    .strip_suffix('/')
                    .unwrap_or(&args.uri_prefix)
                    .to_string(),
                encode_uri(&format!(
                    "{}{}",
                    args.uri_prefix,
                    get_file_name(&args.serve_path)
                )),
            ]
        } else {
            vec![]
        };
        let html = match args.assets.as_ref() {
            Some(path) => Cow::Owned(std::fs::read_to_string(path.join("index.html"))?),
            None => Cow::Borrowed(INDEX_HTML),
        };
        Ok(Self {
            args,
            running,
            single_file_req_paths,
            assets_prefix,
            html,
            auth,
            direct_file_access,
            admin_config: RwLock::new(admin_config),
        })
    }

    /// 首次访问初始化：从数据目录读取已保存的管理员账号（命令行 -a / 配置文件优先）
    fn load_admin_credentials(args: &mut Args) -> Result<()> {
        // 命令行 / 环境变量已配置账号时不读凭据文件
        if args.auth.has_users() {
            return Ok(());
        }
        let config_path = admin_config_path(args);
        let content = match std::fs::read_to_string(&config_path) {
            Ok(v) => v,
            // 不存在（或路径成分不是目录，如单文件模式）= 尚未初始化
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound
                    || err.kind() == std::io::ErrorKind::NotADirectory =>
            {
                return Ok(())
            }
            // 读得到目录却读不了凭据文件：fail-closed，避免无认证裸奔
            Err(err) => {
                bail!(
                    "无法读取管理员配置 {}：{err}。请修复该文件的读取权限后重启",
                    config_path.display()
                )
            }
        };
        let config: AdminConfig = match serde_json::from_str(&content) {
            Ok(v) => v,
            // 凭据文件存在但已损坏：拒绝启动比静默关闭所有认证更安全。
            // 错误信息提示用户修复或删除该文件。
            Err(err) => bail!(
                "管理员配置 {} 已损坏：{err}。\
                 请修复该文件，或删除它并通过网页重新初始化管理员账号",
                config_path.display()
            ),
        };
        let scope = resolve_anonymous_scope(&config);
        let rules = build_auth_rules(&config.user, &config.password, &scope);
        let refs: Vec<&str> = rules.iter().map(|v| v.as_str()).collect();
        args.auth = AccessControl::new(&refs)?;
        // 凭据文件历史上可能以默认 0644 创建，收紧为仅属主可读写
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&config_path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    let _ = std::fs::set_permissions(
                        &config_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
            }
        }
        Ok(())
    }

    pub async fn call(
        self: Arc<Self>,
        req: Request,
        addr: Option<SocketAddr>,
    ) -> Result<Response, hyper::Error> {
        let uri = req.uri().clone();
        // 浏览器请求（带 Sec-Fetch-* 头）收到 401 + WWW-Authenticate 时会强制弹出
        // 原生登录框，页面无法拦截，因此先标记，稍后在响应阶段统一移除该响应头。
        let is_browser_req = is_browser_request(req.headers());
        let assets_prefix = &self.assets_prefix;
        let enable_cors = self.args.enable_cors;
        let mut http_log_data = self.args.http_logger.data(&req);
        if let Some(addr) = addr {
            http_log_data.insert("remote_addr".to_string(), addr.ip().to_string());
        }

        let mut res = match self.clone().handle(req).await {
            Ok(res) => {
                http_log_data.insert("status".to_string(), res.status().as_u16().to_string());
                if !uri.path().starts_with(assets_prefix) {
                    self.args.http_logger.log(&http_log_data, None);
                }
                res
            }
            Err(err) => {
                let mut res = Response::default();
                let status = StatusCode::INTERNAL_SERVER_ERROR;
                *res.status_mut() = status;
                http_log_data.insert("status".to_string(), status.as_u16().to_string());
                self.args
                    .http_logger
                    .log(&http_log_data, Some(err.to_string()));
                res
            }
        };

        if enable_cors {
            add_cors(&mut res);
        }

        // 浏览器登录统一走页面上的登录按钮。若下发 WWW-Authenticate，
        // 浏览器会强制弹出原生账号框（含 fetch/XHR 请求），页面无法拦截。
        // WebDAV 客户端与 curl 不带 Sec-Fetch-* 头，仍保留认证挑战以便原生认证。
        if is_browser_req {
            res.headers_mut().remove("www-authenticate");
        }
        Ok(res)
    }

    pub async fn handle(self: Arc<Self>, req: Request) -> Result<Response> {
        let mut res = Response::default();
        let req_path = req.uri().path();
        let method = req.method().clone();

        let relative_path = match self.resolve_path(req_path) {
            Some(v) => v,
            None => {
                status_bad_request(&mut res, "Invalid Path");
                return Ok(res);
            }
        };

        // 配置目录不对外提供（任何方法、任何鉴权状态都返回 404）；
        // 正常布局下配置在服务根之外，此处仅作误配置时的兜底
        if is_protected_config_path(&self.args, &relative_path) {
            status_not_found(&mut res);
            return Ok(res);
        }

        let headers = req.headers();

        if method == Method::GET
            && self
                .handle_internal(&relative_path, headers, &mut res)
                .await?
        {
            return Ok(res);
        }

        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase())
            .unwrap_or_default();

        let is_microsoft_webdav = user_agent.starts_with("microsoft-webdav-miniredir/");

        if is_microsoft_webdav {
            // microsoft webdav requires this.
            res.headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }

        let authorization = headers.get(AUTHORIZATION);

        let query = req.uri().query().unwrap_or_default();
        let mut query_params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        // 会话 Cookie：浏览器直接导航（打开目录、刷新页面）不会带 Authorization 头，
        // 靠登录时下发的签名 Cookie 保持登录态，避免弹出浏览器原生账号框。
        let session = if authorization.is_none() {
            headers
                .get(hyper::header::COOKIE)
                .and_then(|value| value.to_str().ok())
                .and_then(|cookies| extract_cookie(cookies, SESSION_COOKIE_NAME))
                .and_then(|token| self.auth.read().unwrap().verify_session_token(&token))
        } else {
            None
        };

        // 克隆后再 await：std::sync::RwLock 的 guard 不能跨 await 持有
        let guard = match session {
            // 会话身份同样要过路径级 + 方法级权限校验，
            // 否则路径受限的账号（如仅 @/public）可借 Cookie 越权访问规则外路径
            Some((session_user, paths)) => {
                match paths
                    .guard(&relative_path, &method, Some(&self.args.serve_path))
                    .await
                {
                    Some(ap) => (Some(session_user), Some(ap), false),
                    None => (None, None, false),
                }
            }
            None => {
                let auth = self.auth.read().unwrap().clone();
                auth.guard(
                    &relative_path,
                    &method,
                    authorization,
                    query_params.get("token"),
                    is_microsoft_webdav,
                    &self.args.serve_path,
                )
                .await
            }
        };

        let (user, access_paths, via_token) = guard;
        let (user, access_paths) = match (user, access_paths) {
            (None, None) => {
                // 「仅公开目录」模式下，允许匿名通过完整链接直接读取具体文件（方便分享直链），
                // 但目录本身仍需要权限，所以访客无法浏览目录结构。
                if (method == Method::GET || method == Method::HEAD)
                    && self.auth.read().unwrap().anonymous_root_is_index_only()
                    && self.direct_file_access.load(atomic::Ordering::Relaxed)
                    && self.is_file_path(&relative_path).await
                {
                    (None, AccessPaths::new(AccessPerm::ReadOnly))
                } else if is_browser_navigation(headers) {
                    // 浏览器直接导航或加载子资源（图片/脚本/iframe）时无法附带自定义认证头，
                    // 若返回 401 挑战，浏览器会强制弹出原生登录框（页面无法拦截、取消后仍反复弹）。
                    // 这类请求返回 404，登录统一走页面上的登录按钮。
                    // 前端 fetch/XHR 的 Sec-Fetch-Dest 是 "empty"，不在此列，仍返回 401 以便提示登录。
                    status_not_found(&mut res);
                    return Ok(res);
                } else {
                    self.auth_reject(&mut res)?;
                    return Ok(res);
                }
            }
            (Some(_), None) => {
                status_forbid(&mut res);
                return Ok(res);
            }
            (x, Some(y)) => (x, y),
        };

        // 管理员账号接口：初始化 / 修改密码 / 访问设置（均在鉴权之后处理）
        if method == Method::PUT && relative_path == ADMIN_SETUP_PATH {
            self.handle_admin_setup(req, &mut res, user.clone()).await?;
            return Ok(res);
        }
        if relative_path == ADMIN_SETTINGS_PATH {
            if method == Method::GET {
                self.handle_admin_settings_get(&mut res, user.clone())
                    .await?;
                return Ok(res);
            }
            if method == Method::PUT {
                self.handle_admin_settings(req, &mut res, user.clone())
                    .await?;
                return Ok(res);
            }
        }

        if detect_noscript(&user_agent) {
            query_params.insert("noscript".to_string(), String::new());
        }

        if method.as_str() == "CHECKAUTH" {
            match user.clone() {
                Some(user) => {
                    // 下发会话 Cookie：之后浏览器直接打开目录/刷新都会自动携带身份
                    if let Ok(token) = self.auth.read().unwrap().generate_session_token(&user) {
                        // HTTPS 部署下补 Secure 标志，防止 Cookie 走明文信道泄露
                        let secure = if self.args.tls_cert.is_some() {
                            "; Secure"
                        } else {
                            ""
                        };
                        let cookie = format!(
                            "{SESSION_COOKIE_NAME}={token}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{secure}",
                            crate::auth::SESSION_TOKEN_EXPIRATION_SECS
                        );
                        if let Ok(value) = HeaderValue::from_str(&cookie) {
                            res.headers_mut().append(hyper::header::SET_COOKIE, value);
                        }
                    }
                    *res.body_mut() = body_full(user);
                }
                None => {
                    if has_query_flag(&query_params, "login") || !access_paths.perm().readwrite() {
                        self.auth_reject(&mut res)?
                    } else {
                        *res.body_mut() = body_full("");
                    }
                }
            }
            return Ok(res);
        } else if method.as_str() == "LOGOUT" {
            let cookie =
                format!("{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                res.headers_mut().append(hyper::header::SET_COOKIE, value);
            }
            // 退出登录是正常操作：清除会话 Cookie 后返回 200。
            // 若返回 401 + 认证挑战，浏览器会立刻弹出原生登录框。
            *res.status_mut() = StatusCode::OK;
            return Ok(res);
        }

        let head_only = method == Method::HEAD || method == Method::OPTIONS;

        if has_query_flag(&query_params, "tokengen") {
            // 分享 token 不能再铸造新 token，否则短时效分享链接可以被无限续期
            if via_token {
                self.auth_reject(&mut res)?;
                return Ok(res);
            }
            self.handle_tokengen(&relative_path, user, head_only, &mut res)
                .await?;
            return Ok(res);
        }

        if self.args.path_is_file {
            if self
                .single_file_req_paths
                .iter()
                .any(|v| v.as_str() == req_path)
            {
                self.handle_send_file(&self.args.serve_path, headers, head_only, &mut res)
                    .await?;
            } else {
                self.handle_not_found(&query_params, headers, head_only, &mut res)
                    .await?;
            }
            return Ok(res);
        }
        let path = match self.join_path(&relative_path) {
            Some(v) => v,
            None => {
                status_forbid(&mut res);
                return Ok(res);
            }
        };

        let path = path.as_path();

        let (is_miss, is_dir, is_file, size) = match fs::metadata(path).await.ok() {
            Some(meta) => (false, meta.is_dir(), meta.is_file(), meta.len()),
            None => (true, false, false, 0),
        };

        let allow_upload = self.args.allow_upload;
        let allow_delete = self.args.allow_delete;
        let allow_search = self.args.allow_search;
        let allow_archive = self.args.allow_archive;
        let render_index = self.args.render_index;
        let render_spa = self.args.render_spa;
        let render_try_index = self.args.render_try_index;

        if self.guard_root_contained(path).await {
            self.handle_not_found(&query_params, headers, head_only, &mut res)
                .await?;
            return Ok(res);
        }

        // ?settings 需要管理员身份：浏览器导航改为 302 跳回当前目录页
        // （页面内有登录按钮），避免渲染出空白的 401 页；
        // fetch/API 请求不受影响，仍由 send_index 返回 401。
        if is_dir
            && (method == Method::GET || method == Method::HEAD)
            && has_query_flag(&query_params, "settings")
            && !self.can_manage_settings(&user)
            && is_browser_navigation(headers)
        {
            let target = if req_path.ends_with('/') {
                req_path.to_string()
            } else {
                format!("{req_path}/")
            };
            *res.status_mut() = StatusCode::FOUND;
            if let Ok(value) = HeaderValue::from_str(&target) {
                res.headers_mut().insert(hyper::header::LOCATION, value);
            }
            return Ok(res);
        }

        match method {
            Method::GET | Method::HEAD => {
                if is_dir {
                    if render_try_index {
                        if allow_archive && has_query_flag(&query_params, "zip") {
                            self.handle_zip_dir(path, head_only, access_paths, &mut res)
                                .await?;
                        } else if allow_search && query_params.contains_key("q") {
                            self.handle_search_dir(
                                path,
                                &query_params,
                                head_only,
                                user,
                                access_paths,
                                &mut res,
                            )
                            .await?;
                        } else {
                            self.handle_render_index(
                                path,
                                &query_params,
                                headers,
                                head_only,
                                user,
                                access_paths,
                                &mut res,
                            )
                            .await?;
                        }
                    } else if render_index || render_spa {
                        self.handle_render_index(
                            path,
                            &query_params,
                            headers,
                            head_only,
                            user,
                            access_paths,
                            &mut res,
                        )
                        .await?;
                    } else if has_query_flag(&query_params, "zip") {
                        if !allow_archive {
                            status_not_found(&mut res);
                            return Ok(res);
                        }
                        self.handle_zip_dir(path, head_only, access_paths, &mut res)
                            .await?;
                    } else if allow_search && query_params.contains_key("q") {
                        self.handle_search_dir(
                            path,
                            &query_params,
                            head_only,
                            user,
                            access_paths,
                            &mut res,
                        )
                        .await?;
                    } else {
                        self.handle_ls_dir(
                            path,
                            true,
                            &query_params,
                            head_only,
                            user,
                            access_paths,
                            &mut res,
                        )
                        .await?;
                    }
                } else if is_file {
                    if has_query_flag(&query_params, "json") {
                        self.handle_file_json(path, head_only, &mut res).await?;
                    } else if has_query_flag(&query_params, "edit") {
                        self.handle_edit_file(path, DataKind::Edit, head_only, user, &mut res)
                            .await?;
                    } else if has_query_flag(&query_params, "view") {
                        self.handle_edit_file(path, DataKind::View, head_only, user, &mut res)
                            .await?;
                    } else if has_query_flag(&query_params, "hash") {
                        if self.args.allow_hash {
                            self.handle_hash_file(path, head_only, &mut res).await?;
                        } else {
                            status_forbid(&mut res);
                        }
                    } else {
                        self.handle_send_file(path, headers, head_only, &mut res)
                            .await?;
                    }
                } else if render_spa {
                    self.handle_render_spa(path, &query_params, headers, head_only, &mut res)
                        .await?;
                } else if allow_upload && req_path.ends_with('/') {
                    self.handle_ls_dir(
                        path,
                        false,
                        &query_params,
                        head_only,
                        user,
                        access_paths,
                        &mut res,
                    )
                    .await?;
                } else {
                    self.handle_not_found(&query_params, headers, head_only, &mut res)
                        .await?;
                }
            }
            Method::OPTIONS => {
                set_webdav_headers(&mut res);
            }
            Method::PUT => {
                if is_dir || !allow_upload || (!allow_delete && size > 0) {
                    status_forbid(&mut res);
                } else {
                    self.handle_upload(path, None, size, req, &mut res).await?;
                }
            }
            Method::PATCH => {
                if is_miss {
                    status_not_found(&mut res);
                } else if !allow_upload {
                    status_forbid(&mut res);
                } else {
                    let offset = match parse_upload_offset(headers, size) {
                        Ok(v) => v,
                        Err(err) => {
                            status_bad_request(&mut res, &err.to_string());
                            return Ok(res);
                        }
                    };
                    match offset {
                        Some(offset) => {
                            if offset < size && !allow_delete {
                                status_forbid(&mut res);
                                return Ok(res);
                            }
                            self.handle_upload(path, Some(offset), size, req, &mut res)
                                .await?;
                        }
                        None => {
                            *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                        }
                    }
                }
            }
            Method::DELETE => {
                if !allow_delete {
                    status_forbid(&mut res);
                } else if !is_miss {
                    self.handle_delete(path, is_dir, &mut res).await?
                } else {
                    status_not_found(&mut res);
                }
            }
            method => match method.as_str() {
                "PROPFIND" => {
                    if is_dir {
                        let access_paths =
                            if access_paths.perm().indexonly() && authorization.is_none() {
                                // see https://github.com/sigoden/dufs/issues/229
                                AccessPaths::new(AccessPerm::ReadOnly)
                            } else {
                                access_paths
                            };
                        self.handle_propfind_dir(path, headers, access_paths, &mut res)
                            .await?;
                    } else if is_file {
                        self.handle_propfind_file(path, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "PROPPATCH" => {
                    if is_file {
                        self.handle_proppatch(req_path, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "MKCOL" => {
                    if !allow_upload {
                        status_forbid(&mut res);
                    } else if !is_miss {
                        *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                        *res.body_mut() = body_full("Already exists");
                    } else {
                        self.handle_mkcol(path, &mut res).await?;
                    }
                }
                "COPY" => {
                    if !allow_upload {
                        status_forbid(&mut res);
                    } else if is_miss {
                        status_not_found(&mut res);
                    } else {
                        self.handle_copy(path, &req, &mut res).await?
                    }
                }
                "MOVE" => {
                    if !allow_upload || !allow_delete {
                        status_forbid(&mut res);
                    } else if is_miss {
                        status_not_found(&mut res);
                    } else {
                        self.handle_move(path, &req, &mut res).await?
                    }
                }
                "LOCK" => {
                    // Fake lock
                    if is_file {
                        let has_auth = authorization.is_some();
                        self.handle_lock(req_path, has_auth, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "UNLOCK" => {
                    // Fake unlock
                    if is_miss {
                        status_not_found(&mut res);
                    }
                }
                _ => {
                    *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                }
            },
        }
        Ok(res)
    }

    async fn handle_upload(
        &self,
        path: &Path,
        upload_offset: Option<u64>,
        size: u64,
        req: Request,
        res: &mut Response,
    ) -> Result<()> {
        ensure_path_parent(path).await?;
        let (mut file, status) = match upload_offset {
            None => (fs::File::create(path).await?, StatusCode::CREATED),
            Some(offset) if offset == size => (
                fs::OpenOptions::new().append(true).open(path).await?,
                StatusCode::NO_CONTENT,
            ),
            Some(offset) => {
                let mut file = fs::OpenOptions::new().write(true).open(path).await?;
                file.seek(SeekFrom::Start(offset)).await?;
                (file, StatusCode::NO_CONTENT)
            }
        };
        let stream = IncomingStream::new(req.into_body());

        let body_with_io_error = stream.map_err(io::Error::other);
        let body_reader = StreamReader::new(body_with_io_error);

        pin_mut!(body_reader);

        let ret = io::copy(&mut body_reader, &mut file).await;
        let size = fs::metadata(path)
            .await
            .map(|v| v.len())
            .unwrap_or_default();
        if ret.is_err() {
            if upload_offset.is_none() && size < RESUMABLE_UPLOAD_MIN_SIZE {
                let _ = tokio::fs::remove_file(&path).await;
            }
            ret?;
        }

        *res.status_mut() = status;

        Ok(())
    }

    async fn handle_delete(&self, path: &Path, is_dir: bool, res: &mut Response) -> Result<()> {
        match is_dir {
            true => fs::remove_dir_all(path).await?,
            false => fs::remove_file(path).await?,
        }

        status_no_content(res);
        Ok(())
    }

    async fn handle_ls_dir(
        &self,
        path: &Path,
        exist: bool,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let mut paths = vec![];
        if !head_only && exist {
            paths = match self.list_dir(path, path, access_paths.clone()).await {
                Ok(paths) => paths,
                Err(_) => {
                    status_forbid(res);
                    return Ok(());
                }
            }
        };
        self.send_index(
            path,
            paths,
            exist,
            query_params,
            head_only,
            user,
            access_paths,
            res,
        )
    }

    async fn handle_search_dir(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let mut paths: Vec<PathItem> = vec![];
        let search = query_params
            .get("q")
            .ok_or_else(|| anyhow!("invalid q"))?
            .to_lowercase();
        if search.is_empty() {
            return self
                .handle_ls_dir(path, true, query_params, head_only, user, access_paths, res)
                .await;
        }

        if !head_only {
            let path_buf = path.to_path_buf();
            let hidden = Arc::new(self.args.hidden.to_vec());
            let search = search.clone();
            let running = self.running.clone();
            let allow_symlink = self.args.allow_symlink;
            let serve_path = self.args.serve_path.clone();
            let search_paths_set = access_paths.clone();

            let search_paths = tokio::task::spawn_blocking(move || {
                collect_dir_entries(
                    search_paths_set,
                    running,
                    path_buf,
                    hidden,
                    allow_symlink,
                    serve_path,
                    move |x| get_file_name(x.path()).to_lowercase().contains(&search),
                )
            })
            .await?;

            for search_path in search_paths.into_iter() {
                if let Ok(Some(item)) = self.to_pathitem(search_path, path.to_path_buf()).await {
                    paths.push(item);
                }
            }
        }
        self.send_index(
            path,
            paths,
            true,
            query_params,
            head_only,
            user,
            access_paths,
            res,
        )
    }

    async fn handle_zip_dir(
        &self,
        path: &Path,
        head_only: bool,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let (mut writer, reader) = tokio::io::duplex(BUF_SIZE);
        let filename = try_get_file_name(path)?;
        set_content_disposition(res, false, &format!("{filename}.zip"))?;
        res.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/zip"));
        if head_only {
            return Ok(());
        }
        let path = path.to_owned();
        let hidden = self.args.hidden.clone();
        let running = self.running.clone();
        let compression = self.args.compress.to_compression();
        let follow_symlinks = self.args.allow_symlink;
        let serve_path = self.args.serve_path.clone();
        tokio::spawn(async move {
            if let Err(e) = zip_dir(
                &mut writer,
                &path,
                access_paths,
                &hidden,
                compression,
                follow_symlinks,
                serve_path,
                running,
            )
            .await
            {
                error!("Failed to zip {}, {e}", path.display());
            }
        });
        let reader_stream = ReaderStream::with_capacity(reader, BUF_SIZE);
        let stream_body = StreamBody::new(
            reader_stream
                .map_ok(Frame::data)
                .map_err(|err| anyhow!("{err}")),
        );
        let boxed_body = stream_body.boxed();
        *res.body_mut() = boxed_body;
        Ok(())
    }

    async fn handle_render_index(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let index_path = path.join(INDEX_NAME);
        if fs::metadata(&index_path)
            .await
            .ok()
            .map(|v| v.is_file())
            .unwrap_or_default()
        {
            self.handle_send_file(&index_path, headers, head_only, res)
                .await?;
        } else if self.args.render_try_index {
            self.handle_ls_dir(path, true, query_params, head_only, user, access_paths, res)
                .await?;
        } else {
            self.handle_not_found(query_params, headers, head_only, res)
                .await?;
        }
        Ok(())
    }

    async fn handle_file_json(
        &self,
        path: &Path,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let pathitem = match self.to_pathitem(path, &self.args.serve_path).await? {
            Some(v) => v,
            None => {
                status_not_found(res);
                return Ok(());
            }
        };
        let output = serde_json::to_string_pretty(&pathitem)?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_render_spa(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        if path.extension().is_none() {
            let path = self.args.serve_path.join(INDEX_NAME);
            self.handle_send_file(&path, headers, head_only, res)
                .await?;
        } else {
            self.handle_not_found(query_params, headers, head_only, res)
                .await?;
        }
        Ok(())
    }

    async fn handle_not_found(
        &self,
        query_params: &HashMap<String, String>,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        if let Some(error_page) = &self.args.error_page {
            if !has_query_flag(query_params, "noscript") {
                self.handle_send_file(error_page, headers, head_only, res)
                    .await?;
                *res.status_mut() = StatusCode::NOT_FOUND;
                return Ok(());
            }
        }
        status_not_found(res);
        Ok(())
    }

    /// 当前登录用户是否可以访问管理设置
    fn can_manage_settings(&self, user: &Option<String>) -> bool {
        let Some(user) = user.as_deref() else {
            return false;
        };
        match self.cached_admin_config() {
            Some(config) => config.user == user,
            // 账号由启动参数提供时，任何已登录账号都可进入设置
            None => true,
        }
    }

    /// 同步读取管理员配置（仅启动时使用）
    fn load_admin_config_sync(config_path: &Path) -> Option<AdminConfig> {
        let content = std::fs::read_to_string(config_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// 判断相对路径是否指向一个已存在的具体文件
    async fn is_file_path(&self, relative_path: &str) -> bool {
        match self.join_path(relative_path) {
            Some(path) => fs::metadata(&path)
                .await
                .map(|meta| meta.is_file())
                .unwrap_or(false),
            None => false,
        }
    }

    /// 读取并解析 JSON 请求体（边读边限长 4KB，防止超大 body 撑爆内存）
    async fn read_json_body<T: serde::de::DeserializeOwned>(req: Request) -> Result<T> {
        let stream = IncomingStream::new(req.into_body());
        let body_reader = StreamReader::new(stream.map_err(io::Error::other));
        pin_mut!(body_reader);
        let mut buf = Vec::new();
        body_reader.take(4097).read_to_end(&mut buf).await?;
        if buf.len() > 4096 {
            bail!("payload too large");
        }
        let payload = serde_json::from_slice(&buf)?;
        Ok(payload)
    }

    /// 原子写盘管理员配置：先写临时文件（0600）再改名，断电/磁盘满也不会留下半截 JSON
    async fn write_admin_config_atomic(config_path: &Path, content: &[u8]) -> Result<()> {
        let tmp_path = config_path.with_extension(format!("tmp.{}", Uuid::new_v4().as_simple()));
        let mut tmp = fs::File::create(&tmp_path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.set_permissions(std::fs::Permissions::from_mode(0o600))
                .await?;
        }
        io::AsyncWriteExt::write_all(&mut tmp, content).await?;
        io::AsyncWriteExt::flush(&mut tmp).await?;
        drop(tmp);
        fs::rename(&tmp_path, config_path).await?;
        Ok(())
    }

    /// 保存管理员配置：原子写盘 + 更新内存缓存
    async fn persist_admin_config(&self, config: &AdminConfig) -> Result<()> {
        let config_path = admin_config_path(&self.args);
        // 配置目录可能还不存在（首次初始化），先建好再原子写
        if let Some(dir) = config_path.parent() {
            fs::create_dir_all(dir).await?;
        }
        let content = serde_json::to_vec_pretty(config)?;
        if let Err(err) = Self::write_admin_config_atomic(&config_path, &content).await {
            log::error!("failed to save admin config: {err}");
            bail!("cannot persist config");
        }
        *self.admin_config.write().unwrap_or_else(|e| e.into_inner()) = Some(config.clone());
        Ok(())
    }

    fn cached_admin_config(&self) -> Option<AdminConfig> {
        self.admin_config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 确保访客公开目录存在：访客范围切换为 public 时，前端会把匿名访客
    /// 引导到 /public/，目录不存在就是一个 404，所以这里自动补建目录与
    /// 说明文件。已有内容一律不动（不覆盖同名文件）。
    async fn ensure_public_dir(&self, scope: &str) {
        if scope != "public" {
            return;
        }
        let public_dir = self.args.serve_path.join(PUBLIC_DIR_NAME);
        if let Err(err) = fs::create_dir_all(&public_dir).await {
            log::warn!(
                "failed to create public dir {}: {err}",
                public_dir.display()
            );
            return;
        }
        let readme = public_dir.join("README.txt");
        if fs::symlink_metadata(&readme).await.is_ok() {
            return;
        }
        if let Err(err) = fs::write(&readme, PUBLIC_DIR_README).await {
            log::warn!("failed to write {}: {err}", readme.display());
        }
    }

    /// 管理员账号接口：未配置账号时用于首次初始化，已配置时用于修改密码
    async fn handle_admin_setup(
        &self,
        req: Request,
        res: &mut Response,
        user: Option<String>,
    ) -> Result<()> {
        // 已经有账号体系（命令行 -a / 配置文件 / 已初始化）时，走「修改密码」流程
        if self.auth.read().unwrap().has_users() {
            return self.handle_admin_update(req, res, user).await;
        }

        let payload: AdminSetupPayload = match Self::read_json_body(req).await {
            Ok(v) => v,
            Err(_) => {
                status_bad_request(res, "invalid payload");
                return Ok(());
            }
        };

        let user = payload.user.trim().to_string();
        let password = payload.password;
        // `|` 和 `/` 会破坏鉴权规则的拼装语法（`|` 是规则分隔符），
        // 控制字符则可能污染规则串与日志
        if user.is_empty()
            || user.len() > 64
            || password.len() < 4
            || password.len() > 128
            || user.contains(':')
            || user.contains('@')
            || user.contains('|')
            || user.contains('/')
            || user.chars().any(|c| c.is_ascii_control())
        {
            status_bad_request(res, "invalid username or password");
            return Ok(());
        }

        let salt = Uuid::new_v4().as_simple().to_string();
        let hashed =
            match ShaCrypt::SHA512.hash_password_with_salt(password.as_bytes(), salt.as_bytes()) {
                Ok(v) => v.to_string(),
                Err(_) => {
                    status_bad_request(res, "failed to hash password");
                    return Ok(());
                }
            };

        let scope = match payload.anonymous_scope.as_deref() {
            Some(v) if ["all", "public", "none"].contains(&v) => v.to_string(),
            _ if payload.allow_anonymous_read => "all".to_string(),
            _ => "none".to_string(),
        };
        // 匿名直链默认关闭（文件分享服务器可按需在设置页开启）
        let direct_file_access = payload.allow_direct_file_access.unwrap_or(false);
        let config = AdminConfig {
            user: user.clone(),
            password: hashed.clone(),
            allow_anonymous_read: scope != "none",
            anonymous_scope: Some(scope.clone()),
            allow_direct_file_access: direct_file_access,
        };
        // 先落盘再更新运行时状态：写盘失败时内存与磁盘保持一致
        if let Err(err) = self.persist_admin_config(&config).await {
            status_bad_request(res, &err.to_string());
            return Ok(());
        }
        self.direct_file_access
            .store(direct_file_access, atomic::Ordering::Relaxed);

        let rules = build_auth_rules(&user, &hashed, &scope);
        let refs: Vec<&str> = rules.iter().map(|v| v.as_str()).collect();
        *self.auth.write().unwrap() = AccessControl::new(&refs)?;
        // 推荐的「仅公开目录」模式需要 /public 才有意义，初始化时自动补建
        self.ensure_public_dir(&scope).await;

        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
        *res.status_mut() = StatusCode::OK;
        *res.body_mut() = body_full(r#"{"status":"OK"}"#);
        Ok(())
    }

    /// 已登录管理员修改密码（账号由网页初始化创建、保存在数据目录时可用）
    async fn handle_admin_update(
        &self,
        req: Request,
        res: &mut Response,
        user: Option<String>,
    ) -> Result<()> {
        let mut config = match self.cached_admin_config() {
            Some(v) => v,
            None => {
                // 账号来自启动参数或配置文件，网页不支持修改
                status_forbid(res);
                return Ok(());
            }
        };

        // 只允许该管理员本人修改（登录凭据已由鉴权流程校验）
        if user.as_deref() != Some(config.user.as_str()) {
            status_forbid(res);
            return Ok(());
        }

        let payload: AdminPasswordPayload = match Self::read_json_body(req).await {
            Ok(v) => v,
            Err(_) => {
                status_bad_request(res, "invalid payload");
                return Ok(());
            }
        };
        let password = payload.password;
        if password.len() < 4 || password.len() > 128 {
            status_bad_request(res, "invalid password");
            return Ok(());
        }

        let salt = Uuid::new_v4().as_simple().to_string();
        let hashed =
            match ShaCrypt::SHA512.hash_password_with_salt(password.as_bytes(), salt.as_bytes()) {
                Ok(v) => v.to_string(),
                Err(_) => {
                    status_bad_request(res, "failed to hash password");
                    return Ok(());
                }
            };

        config.password = hashed.clone();
        if let Err(err) = self.persist_admin_config(&config).await {
            status_bad_request(res, &err.to_string());
            return Ok(());
        }

        let scope = resolve_anonymous_scope(&config);
        let rules = build_auth_rules(&config.user, &hashed, &scope);
        let refs: Vec<&str> = rules.iter().map(|v| v.as_str()).collect();
        *self.auth.write().unwrap() = AccessControl::new(&refs)?;

        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
        *res.status_mut() = StatusCode::OK;
        *res.body_mut() = body_full(r#"{"status":"OK"}"#);
        Ok(())
    }

    /// 读取当前访问设置（仅管理员本人）
    async fn handle_admin_settings_get(
        &self,
        res: &mut Response,
        user: Option<String>,
    ) -> Result<()> {
        let config = match self.cached_admin_config() {
            Some(v) => v,
            None => {
                status_forbid(res);
                return Ok(());
            }
        };
        if user.as_deref() != Some(config.user.as_str()) {
            status_forbid(res);
            return Ok(());
        }
        let payload = serde_json::json!({
            "user": config.user,
            "anonymous_scope": resolve_anonymous_scope(&config),
            "allow_direct_file_access": config.allow_direct_file_access,
            "serve_path": self.args.serve_path.display().to_string(),
            "config_dir": admin_config_dir(&self.args).display().to_string(),
            "version": env!("CARGO_PKG_VERSION"),
        });
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
        *res.status_mut() = StatusCode::OK;
        *res.body_mut() = body_full(payload.to_string());
        Ok(())
    }

    /// 更新访问设置：访客免登录可见范围（all | public | none）
    async fn handle_admin_settings(
        &self,
        req: Request,
        res: &mut Response,
        user: Option<String>,
    ) -> Result<()> {
        let mut config = match self.cached_admin_config() {
            Some(v) => v,
            None => {
                status_forbid(res);
                return Ok(());
            }
        };
        if user.as_deref() != Some(config.user.as_str()) {
            status_forbid(res);
            return Ok(());
        }

        let payload: AdminSettingsPayload = match Self::read_json_body(req).await {
            Ok(v) => v,
            Err(_) => {
                status_bad_request(res, "invalid payload");
                return Ok(());
            }
        };
        let scope = payload.anonymous_scope.trim().to_string();
        if !["all", "public", "none"].contains(&scope.as_str()) {
            status_bad_request(res, "invalid scope");
            return Ok(());
        }

        config.anonymous_scope = Some(scope.clone());
        config.allow_anonymous_read = scope != "none";
        if let Some(direct) = payload.allow_direct_file_access {
            config.allow_direct_file_access = direct;
        }
        // 先落盘再更新运行时状态：写盘失败时内存与磁盘保持一致
        if let Err(err) = self.persist_admin_config(&config).await {
            status_bad_request(res, &err.to_string());
            return Ok(());
        }
        self.direct_file_access
            .store(config.allow_direct_file_access, atomic::Ordering::Relaxed);

        let rules = build_auth_rules(&config.user, &config.password, &scope);
        let refs: Vec<&str> = rules.iter().map(|v| v.as_str()).collect();
        *self.auth.write().unwrap() = AccessControl::new(&refs)?;
        // 切到「仅公开目录」时同样补建 /public，避免访客被引导到空目录
        self.ensure_public_dir(&scope).await;

        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
        *res.status_mut() = StatusCode::OK;
        *res.body_mut() = body_full(r#"{"status":"OK"}"#);
        Ok(())
    }

    async fn handle_internal(
        &self,
        req_path: &str,
        headers: &HeaderMap<HeaderValue>,
        res: &mut Response,
    ) -> Result<bool> {
        if let Some(name) = req_path.strip_prefix(&self.assets_prefix) {
            match self.args.assets.as_ref() {
                Some(assets_path) => {
                    let path = match join_within(assets_path, name) {
                        Some(path) => path,
                        None => {
                            status_not_found(res);
                            return Ok(true);
                        }
                    };
                    if path.exists() {
                        self.handle_send_file(&path, headers, false, res).await?;
                    } else {
                        status_not_found(res);
                        return Ok(true);
                    }
                }
                None => match name {
                    "index.js" => {
                        *res.body_mut() = body_full(INDEX_JS);
                        res.headers_mut().insert(
                            "content-type",
                            HeaderValue::from_static("application/javascript; charset=UTF-8"),
                        );
                    }
                    "index.css" => {
                        *res.body_mut() = body_full(INDEX_CSS);
                        res.headers_mut().insert(
                            "content-type",
                            HeaderValue::from_static("text/css; charset=UTF-8"),
                        );
                    }
                    "favicon.ico" => {
                        *res.body_mut() = body_full(FAVICON_ICO);
                        res.headers_mut()
                            .insert("content-type", HeaderValue::from_static("image/x-icon"));
                    }
                    _ => {
                        status_not_found(res);
                    }
                },
            }
            res.headers_mut().insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            );
            res.headers_mut().insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
            Ok(true)
        } else if req_path == HEALTH_CHECK_PATH {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));

            *res.body_mut() = body_full(r#"{"status":"OK"}"#);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn handle_send_file(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let (file, meta) = tokio::join!(fs::File::open(path), fs::metadata(path),);
        let (mut file, meta) = (file?, meta?);
        let size = meta.len();
        let mut use_range = true;
        if let Some((etag, last_modified)) = extract_cache_headers(&meta) {
            if let Some(if_unmodified_since) = headers.typed_get::<IfUnmodifiedSince>() {
                if !if_unmodified_since.precondition_passes(last_modified.into()) {
                    *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                    return Ok(());
                }
            }
            if let Some(if_match) = headers.typed_get::<IfMatch>() {
                if !if_match.precondition_passes(&etag) {
                    *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                    return Ok(());
                }
            }
            if let Some(if_modified_since) = headers.typed_get::<IfModifiedSince>() {
                if !if_modified_since.is_modified(last_modified.into()) {
                    *res.status_mut() = StatusCode::NOT_MODIFIED;
                    return Ok(());
                }
            }
            if let Some(if_none_match) = headers.typed_get::<IfNoneMatch>() {
                if !if_none_match.precondition_passes(&etag) {
                    *res.status_mut() = StatusCode::NOT_MODIFIED;
                    return Ok(());
                }
            }

            res.headers_mut()
                .typed_insert(CacheControl::new().with_no_cache());
            res.headers_mut().typed_insert(last_modified);
            res.headers_mut().typed_insert(etag.clone());

            if headers.typed_get::<Range>().is_some() {
                use_range = headers
                    .typed_get::<IfRange>()
                    .map(|if_range| !if_range.is_modified(Some(&etag), Some(&last_modified)))
                    // Always be fresh if there is no validators
                    .unwrap_or(true);
            } else {
                use_range = false;
            }
        }

        let ranges = if use_range {
            headers.get(RANGE).map(|range| {
                range
                    .to_str()
                    .ok()
                    .and_then(|range| parse_range(range, size))
            })
        } else {
            None
        };

        let content_type = get_content_type(path, &mut file).await?;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_str(&content_type)?);

        let filename = try_get_file_name(path)?;
        set_content_disposition(res, true, filename)?;

        res.headers_mut().typed_insert(AcceptRanges::bytes());

        if let Some(ranges) = ranges {
            if let Some(ranges) = ranges {
                if ranges.len() == 1 {
                    let (start, end) = ranges[0];
                    file.seek(SeekFrom::Start(start)).await?;
                    let range_size = end - start + 1;
                    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let content_range = format!("bytes {start}-{end}/{size}");
                    res.headers_mut()
                        .insert(CONTENT_RANGE, content_range.parse()?);
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, format!("{range_size}").parse()?);
                    if head_only {
                        return Ok(());
                    }

                    let stream_body = StreamBody::new(
                        LengthLimitedStream::new(file, range_size as usize)
                            .map_ok(Frame::data)
                            .map_err(|err| anyhow!("{err}")),
                    );
                    let boxed_body = stream_body.boxed();
                    *res.body_mut() = boxed_body;
                } else {
                    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let boundary = Uuid::new_v4();
                    let footer = format!("--{boundary}--\r\n");

                    // 预先算出精确长度，HEAD 请求（以及 Content-Length 头）无需读文件
                    let mut content_length = footer.len();
                    for (start, end) in &ranges {
                        let range_size = end - start + 1;
                        let part_header = format!(
                            "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {start}-{end}/{size}\r\n\r\n",
                        );
                        content_length = content_length
                            .saturating_add(part_header.len())
                            .saturating_add(usize::try_from(range_size).unwrap_or(usize::MAX))
                            .saturating_add(2);
                    }

                    res.headers_mut().insert(
                        CONTENT_TYPE,
                        format!("multipart/byteranges; boundary={boundary}").parse()?,
                    );
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, format!("{content_length}").parse()?);
                    if head_only {
                        return Ok(());
                    }

                    // 逐段流式输出，而不是把整个响应体读进内存
                    let stream = async_stream::try_stream! {
                        let mut buffer = vec![0; BUF_SIZE];
                        for (start, end) in ranges {
                            file.seek(SeekFrom::Start(start)).await?;
                            let part_header = format!(
                                "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {start}-{end}/{size}\r\n\r\n",
                            );
                            yield Bytes::from(part_header);
                            let mut remaining = end - start + 1;
                            while remaining > 0 {
                                let want = remaining.min(BUF_SIZE as u64) as usize;
                                file.read_exact(&mut buffer[..want]).await?;
                                yield Bytes::copy_from_slice(&buffer[..want]);
                                remaining -= want as u64;
                            }
                            yield Bytes::from_static(b"\r\n");
                        }
                        yield Bytes::from(footer);
                    };
                    let stream_body = StreamBody::new(
                        stream
                            .map_ok(Frame::data)
                            .map_err(|err: io::Error| anyhow::Error::new(err)),
                    );
                    *res.body_mut() = stream_body.boxed();
                }
            } else {
                *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                res.headers_mut()
                    .insert(CONTENT_RANGE, format!("bytes */{size}").parse()?);
            }
        } else {
            res.headers_mut()
                .insert(CONTENT_LENGTH, format!("{size}").parse()?);
            if head_only {
                return Ok(());
            }

            let reader_stream = ReaderStream::with_capacity(file, BUF_SIZE);
            let stream_body = StreamBody::new(
                reader_stream
                    .map_ok(Frame::data)
                    .map_err(|err| anyhow!("{err}")),
            );
            let boxed_body = stream_body.boxed();
            *res.body_mut() = boxed_body;
        }
        Ok(())
    }

    async fn handle_edit_file(
        &self,
        path: &Path,
        kind: DataKind,
        head_only: bool,
        user: Option<String>,
        res: &mut Response,
    ) -> Result<()> {
        let (file, meta) = tokio::join!(fs::File::open(path), fs::metadata(path),);
        let (file, meta) = (file?, meta?);
        let href = format!(
            "/{}",
            normalize_path(path.strip_prefix(&self.args.serve_path)?)
        );
        let mut buffer: Vec<u8> = vec![];
        file.take(1024).read_to_end(&mut buffer).await?;
        let editable =
            meta.len() <= EDITABLE_TEXT_MAX_SIZE && content_inspector::inspect(&buffer).is_text();
        let data = EditData {
            href,
            kind,
            uri_prefix: self.args.uri_prefix.clone(),
            allow_upload: self.args.allow_upload,
            allow_delete: self.args.allow_delete,
            auth: self.auth.read().unwrap().has_users(),
            user,
            editable,
        };
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
        let index_data = STANDARD.encode(serde_json::to_string(&data)?);
        let output = self
            .html
            .replace(
                "__ASSETS_PREFIX__",
                &format!("{}{}", self.args.uri_prefix, self.assets_prefix),
            )
            .replace("__INDEX_DATA__", &index_data);
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_no_cache());
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_hash_file(
        &self,
        path: &Path,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let output = sha256_file(path).await?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_tokengen(
        &self,
        relative_path: &str,
        user: Option<String>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let user = match user {
            Some(user) => user,
            None => {
                self.auth_reject(res)?;
                return Ok(());
            }
        };
        let output = self
            .auth
            .read()
            .unwrap()
            .generate_token(relative_path, &user)?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_PLAIN_UTF_8));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        if !head_only {
            *res.body_mut() = body_full(output);
        }
        Ok(())
    }

    async fn handle_propfind_dir(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        let depth: u32 = match headers.get("depth") {
            Some(v) => match v.to_str().ok().and_then(|v| v.parse().ok()) {
                Some(0) => 0,
                Some(1) => 1,
                _ => {
                    status_bad_request(res, "Invalid depth: only 0 and 1 are allowed.");
                    return Ok(());
                }
            },
            None => 1,
        };
        let mut paths = match self.to_pathitem(path, &self.args.serve_path).await? {
            Some(v) => vec![v],
            None => vec![],
        };
        if depth == 1 {
            match self
                .list_dir(path, &self.args.serve_path, access_paths)
                .await
            {
                Ok(child) => paths.extend(child),
                Err(_) => {
                    status_forbid(res);
                    return Ok(());
                }
            }
        }
        let output = paths
            .iter()
            .map(|v| v.to_dav_xml(self.args.uri_prefix.as_str()))
            .fold(String::new(), |mut acc, v| {
                acc.push_str(&v);
                acc
            });
        res_multistatus(res, &output);
        Ok(())
    }

    async fn handle_propfind_file(&self, path: &Path, res: &mut Response) -> Result<()> {
        if let Some(pathitem) = self.to_pathitem(path, &self.args.serve_path).await? {
            res_multistatus(res, &pathitem.to_dav_xml(self.args.uri_prefix.as_str()));
        } else {
            status_not_found(res);
        }
        Ok(())
    }

    async fn handle_mkcol(&self, path: &Path, res: &mut Response) -> Result<()> {
        fs::create_dir_all(path).await?;
        *res.status_mut() = StatusCode::CREATED;
        Ok(())
    }

    async fn handle_copy(&self, path: &Path, req: &Request, res: &mut Response) -> Result<()> {
        let dest = match self.extract_dest(req, res).await {
            Some(dest) => dest,
            None => {
                return Ok(());
            }
        };

        let meta = fs::symlink_metadata(path).await?;
        if meta.is_dir() {
            status_forbid(res);
            return Ok(());
        }

        if self.guard_root_contained(&dest).await {
            status_bad_request(res, "Invalid Destination");
            return Ok(());
        }

        ensure_path_parent(&dest).await?;

        let overwrite = req
            .headers()
            .get("overwrite")
            .map(|v| v.as_bytes() != b"F")
            .unwrap_or(true);
        if fs::symlink_metadata(&dest).await.is_ok() {
            if !overwrite {
                *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                return Ok(());
            }
            // 覆盖已有目标等价于一次删除，需要显式的删除权限
            if !self.args.allow_delete {
                status_forbid(res);
                return Ok(());
            }
        }

        fs::copy(path, &dest).await?;

        status_no_content(res);
        Ok(())
    }

    async fn handle_move(&self, path: &Path, req: &Request, res: &mut Response) -> Result<()> {
        let dest = match self.extract_dest(req, res).await {
            Some(dest) => dest,
            None => {
                return Ok(());
            }
        };

        if self.guard_root_contained(&dest).await {
            status_bad_request(res, "Invalid Destination");
            return Ok(());
        }

        ensure_path_parent(&dest).await?;

        fs::rename(path, &dest).await?;

        status_no_content(res);
        Ok(())
    }

    async fn handle_lock(&self, req_path: &str, auth: bool, res: &mut Response) -> Result<()> {
        let token = if auth {
            format!("opaquelocktoken:{}", Uuid::new_v4())
        } else {
            Utc::now().timestamp().to_string()
        };

        res.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
        res.headers_mut()
            .insert("lock-token", format!("<{token}>").parse()?);

        *res.body_mut() = body_full(format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>
<D:locktoken><D:href>{token}</D:href></D:locktoken>
<D:lockroot><D:href>{req_path}</D:href></D:lockroot>
</D:activelock></D:lockdiscovery></D:prop>"#
        ));
        Ok(())
    }

    async fn handle_proppatch(&self, req_path: &str, res: &mut Response) -> Result<()> {
        let output = format!(
            r#"<D:response>
<D:href>{req_path}</D:href>
<D:propstat>
<D:prop>
</D:prop>
<D:status>HTTP/1.1 403 Forbidden</D:status>
</D:propstat>
</D:response>"#
        );
        res_multistatus(res, &output);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn send_index(
        &self,
        path: &Path,
        mut paths: Vec<PathItem>,
        exist: bool,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        if has_query_flag(query_params, "settings") && !self.can_manage_settings(&user) {
            self.auth_reject(res)?;
            return Ok(());
        }
        if let Some(sort) = query_params.get("sort") {
            if sort == "name" {
                paths.sort_by(|v1, v2| v1.sort_by_name(v2))
            } else if sort == "mtime" {
                paths.sort_by(|v1, v2| v1.sort_by_mtime(v2))
            } else if sort == "size" {
                paths.sort_by(|v1, v2| v1.sort_by_size(v2))
            }
            if query_params
                .get("order")
                .map(|v| v == "desc")
                .unwrap_or_default()
            {
                paths.reverse();
                // 降序时目录仍然成组置顶（组内按倒序）
                paths.sort_by_key(|v| !v.path_type.is_dir());
            }
        } else {
            paths.sort_by(|v1, v2| v1.sort_by_name(v2))
        }
        // 公开目录置顶（稳定排序，其余条目相对顺序不变）
        paths.sort_by_key(|v| std::cmp::Reverse(v.is_public_dir()));

        if has_query_flag(query_params, "simple") {
            let output = paths
                .into_iter()
                .map(|v| {
                    let displayname = escape_str_pcdata(&v.name);
                    if v.is_dir() {
                        format!("{}/\n", displayname)
                    } else {
                        format!("{}\n", displayname)
                    }
                })
                .collect::<Vec<String>>()
                .join("");
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
            res.headers_mut()
                .typed_insert(ContentLength(output.len() as u64));
            if !head_only {
                *res.body_mut() = body_full(output);
            }
            return Ok(());
        }
        let href = format!(
            "/{}",
            normalize_path(path.strip_prefix(&self.args.serve_path)?)
        );
        let readwrite = access_paths.perm().readwrite();
        let is_settings = has_query_flag(query_params, "settings");
        let admin_config = self.cached_admin_config();
        let anonymous_scope = admin_config
            .as_ref()
            .map(resolve_anonymous_scope)
            .unwrap_or_else(|| "none".to_string());
        let allow_direct_file_access = admin_config
            .as_ref()
            .map(|config| config.allow_direct_file_access)
            .unwrap_or(false);
        let data = IndexData {
            kind: if is_settings {
                DataKind::Settings
            } else {
                DataKind::Index
            },
            href,
            uri_prefix: self.args.uri_prefix.clone(),
            allow_upload: self.args.allow_upload && readwrite,
            allow_delete: self.args.allow_delete && readwrite,
            allow_search: self.args.allow_search,
            allow_archive: self.args.allow_archive,
            dir_exists: exist,
            auth: self.auth.read().unwrap().has_users(),
            user,
            paths,
            public_only: self.auth.read().unwrap().anonymous_root_is_index_only(),
            anonymous_scope,
            allow_direct_file_access,
            serve_path: self.args.serve_path.display().to_string(),
            config_dir: admin_config_dir(&self.args).display().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let output = if has_query_flag(query_params, "json") {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
            serde_json::to_string_pretty(&data)?
        } else if has_query_flag(query_params, "noscript") {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
            generate_noscript_html(&data)?
        } else {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));

            let index_data = STANDARD.encode(serde_json::to_string(&data)?);
            self.html
                .replace(
                    "__ASSETS_PREFIX__",
                    &format!("{}{}", self.args.uri_prefix, self.assets_prefix),
                )
                .replace("__INDEX_DATA__", &index_data)
        };
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_no_cache());
        res.headers_mut().insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    fn auth_reject(&self, res: &mut Response) -> Result<()> {
        set_webdav_headers(res);

        www_authenticate(res, &self.args)?;
        *res.status_mut() = StatusCode::UNAUTHORIZED;
        Ok(())
    }

    async fn guard_root_contained(&self, path: &Path) -> bool {
        if self.args.allow_symlink {
            return false;
        }
        // 逐级上溯到第一个真实存在的祖先再判定：一次性 PUT 深层新路径
        // （父目录不存在）时不能被误判为越界
        let mut check_path = path.to_path_buf();
        while fs::symlink_metadata(&check_path).await.is_err() {
            match check_path.parent() {
                Some(parent) => check_path = parent.to_path_buf(),
                None => return true,
            }
        }
        !self.is_root_contained(check_path.as_path()).await
    }

    async fn is_root_contained(&self, path: &Path) -> bool {
        fs::canonicalize(path)
            .await
            .ok()
            .map(|v| v.starts_with(&self.args.serve_path))
            .unwrap_or_default()
    }

    async fn extract_dest(&self, req: &Request, res: &mut Response) -> Option<PathBuf> {
        let headers = req.headers();
        let dest_path = match self
            .extract_destination_header(headers)
            .and_then(|dest| self.resolve_path(&dest))
        {
            Some(dest) => dest,
            None => {
                status_bad_request(res, "Invalid Destination");
                return None;
            }
        };

        // 配置目录同样不允许作为 MOVE/COPY 的目标：
        // 否则初始化窗口内可先 PUT 任意 JSON 再改名植入，绕过全部校验
        if is_protected_config_path(&self.args, &dest_path) {
            status_forbid(res);
            return None;
        }

        let authorization = headers.get(AUTHORIZATION);
        // 克隆后再 await：std::sync::RwLock 的 guard 不能跨 await 持有
        let auth = self.auth.read().unwrap().clone();
        let guard = auth
            .guard(
                &dest_path,
                req.method(),
                authorization,
                None,
                false,
                &self.args.serve_path,
            )
            .await;

        match guard {
            (_, Some(_), _) => {}
            _ => {
                status_forbid(res);
                return None;
            }
        };

        let dest = match self.join_path(&dest_path) {
            Some(dest) => dest,
            None => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                return None;
            }
        };

        Some(dest)
    }

    fn extract_destination_header(&self, headers: &HeaderMap<HeaderValue>) -> Option<String> {
        let dest = headers.get("Destination")?.to_str().ok()?;
        let uri: Uri = dest.parse().ok()?;
        Some(uri.path().to_string())
    }

    fn resolve_path(&self, path: &str) -> Option<String> {
        let path = decode_uri(path)?;
        let path = path.trim_matches('/');
        let mut parts = vec![];
        for comp in Path::new(path).components() {
            if let Component::Normal(v) = comp {
                let v = v.to_string_lossy();
                if cfg!(windows) {
                    let chars: Vec<char> = v.chars().collect();
                    if chars.len() == 2 && chars[1] == ':' && chars[0].is_ascii_alphabetic() {
                        return None;
                    }
                }
                parts.push(v);
            } else {
                return None;
            }
        }
        let new_path = parts.join("/");
        let path_prefix = self.args.path_prefix.as_str();
        if path_prefix.is_empty() {
            return Some(new_path);
        }
        // 前缀剥离必须落在 / 分隔符边界上：`prefix` 不能匹配 `/prefixfile`
        if new_path == path_prefix {
            return Some(String::new());
        }
        new_path
            .strip_prefix(&format!("{path_prefix}/"))
            .map(|v| v.trim_matches('/').to_string())
    }

    fn join_path(&self, path: &str) -> Option<PathBuf> {
        if path.is_empty() {
            return Some(self.args.serve_path.clone());
        }
        let path = if cfg!(windows) {
            path.replace('/', "\\")
        } else {
            path.to_string()
        };
        join_within(&self.args.serve_path, &path)
    }

    async fn list_dir(
        &self,
        entry_path: &Path,
        base_path: &Path,
        access_paths: AccessPaths,
    ) -> Result<Vec<PathItem>> {
        let mut paths: Vec<PathItem> = vec![];
        if access_paths.perm().indexonly() {
            for name in access_paths.child_names() {
                let entry_path = entry_path.join(name);
                self.add_pathitem(&mut paths, base_path, &entry_path).await;
            }
        } else {
            let mut rd = fs::read_dir(entry_path).await?;
            while let Ok(Some(entry)) = rd.next_entry().await {
                let entry_path = entry.path();
                self.add_pathitem(&mut paths, base_path, &entry_path).await;
            }
        }
        Ok(paths)
    }

    async fn add_pathitem(&self, paths: &mut Vec<PathItem>, base_path: &Path, entry_path: &Path) {
        let base_name = get_file_name(entry_path);
        if let Ok(Some(item)) = self.to_pathitem(entry_path, base_path).await {
            if is_hidden(&self.args.hidden, base_name, item.is_dir()) {
                return;
            }
            paths.push(item);
        }
    }

    async fn to_pathitem<P: AsRef<Path>>(&self, path: P, base_path: P) -> Result<Option<PathItem>> {
        let path = path.as_ref();
        let (meta, meta2) = tokio::join!(fs::metadata(&path), fs::symlink_metadata(&path));
        let (meta, meta2) = (meta?, meta2?);
        let is_symlink = meta2.is_symlink();
        if !self.args.allow_symlink && is_symlink && !self.is_root_contained(path).await {
            return Ok(None);
        }
        let is_dir = meta.is_dir();
        let path_type = match (is_symlink, is_dir) {
            (true, true) => PathType::SymlinkDir,
            (false, true) => PathType::Dir,
            (true, false) => PathType::SymlinkFile,
            (false, false) => PathType::File,
        };
        let mtime = match meta.modified().ok().or_else(|| meta.created().ok()) {
            Some(v) => to_timestamp(&v),
            None => 0,
        };
        let size = match path_type {
            PathType::Dir | PathType::SymlinkDir => {
                let mut count = 0;
                let mut entries = tokio::fs::read_dir(&path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    let entry_path = entry.path();
                    let base_name = get_file_name(&entry_path);
                    let is_dir = entry
                        .file_type()
                        .await
                        .map(|v| v.is_dir())
                        .unwrap_or_default();
                    if is_hidden(&self.args.hidden, base_name, is_dir) {
                        continue;
                    }
                    count += 1;
                    if count >= MAX_SUBPATHS_COUNT {
                        break;
                    }
                }
                count
            }
            PathType::File | PathType::SymlinkFile => meta.len(),
        };
        let rel_path = path.strip_prefix(base_path)?;
        let name = normalize_path(rel_path);
        Ok(Some(PathItem {
            path_type,
            name,
            mtime,
            size,
        }))
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub enum DataKind {
    Index,
    Edit,
    View,
    Settings,
}

#[derive(Debug, Serialize)]
pub struct IndexData {
    pub href: String,
    pub kind: DataKind,
    pub uri_prefix: String,
    pub allow_upload: bool,
    pub allow_delete: bool,
    pub allow_search: bool,
    pub allow_archive: bool,
    pub dir_exists: bool,
    pub auth: bool,
    pub user: Option<String>,
    pub paths: Vec<PathItem>,
    /// 是否处于「匿名仅可访问部分子目录」模式（前端据此引导匿名访客）
    pub public_only: bool,
    /// 当前访客可见范围：all | public | none
    pub anonymous_scope: String,
    /// 是否允许匿名直链读取文件
    pub allow_direct_file_access: bool,
    /// 服务目录与版本（设置页展示）
    pub serve_path: String,
    /// 管理员配置目录（设置页展示）
    pub config_dir: String,
    pub version: String,
}

#[derive(Debug, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct PathItem {
    pub path_type: PathType,
    pub name: String,
    pub mtime: u64,
    pub size: u64,
}

impl PathItem {
    pub fn is_dir(&self) -> bool {
        self.path_type == PathType::Dir || self.path_type == PathType::SymlinkDir
    }

    pub fn to_dav_xml(&self, prefix: &str) -> String {
        let mtime = match Utc.timestamp_millis_opt(self.mtime as i64) {
            LocalResult::Single(v) => format!("{}", v.format("%a, %d %b %Y %H:%M:%S GMT")),
            _ => String::new(),
        };
        let mut href = encode_uri(&format!("{}{}", prefix, self.name));
        if self.is_dir() && !href.ends_with('/') {
            href.push('/');
        }
        let displayname = escape_str_pcdata(self.base_name());
        match self.path_type {
            PathType::Dir | PathType::SymlinkDir => format!(
                r#"<D:response>
<D:href>{href}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{displayname}</D:displayname>
<D:getlastmodified>{mtime}</D:getlastmodified>
<D:resourcetype><D:collection/></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#
            ),
            PathType::File | PathType::SymlinkFile => format!(
                r#"<D:response>
<D:href>{href}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{displayname}</D:displayname>
<D:getcontentlength>{}</D:getcontentlength>
<D:getlastmodified>{mtime}</D:getlastmodified>
<D:resourcetype></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#,
                self.size
            ),
        }
    }

    pub fn base_name(&self) -> &str {
        self.name.split('/').next_back().unwrap_or_default()
    }

    /// 是否为访客公开目录（用于置顶与高亮）
    pub fn is_public_dir(&self) -> bool {
        self.is_dir() && self.name == PUBLIC_DIR_NAME
    }

    pub fn sort_by_name(&self, other: &Self) -> Ordering {
        match self.path_type.cmp(&other.path_type) {
            Ordering::Equal => {
                alphanumeric_sort::compare_str(self.name.to_lowercase(), other.name.to_lowercase())
            }
            v => v,
        }
    }

    pub fn sort_by_mtime(&self, other: &Self) -> Ordering {
        match self.path_type.cmp(&other.path_type) {
            Ordering::Equal => self.mtime.cmp(&other.mtime),
            v => v,
        }
    }

    pub fn sort_by_size(&self, other: &Self) -> Ordering {
        match self.path_type.cmp(&other.path_type) {
            Ordering::Equal => self.size.cmp(&other.size),
            v => v,
        }
    }
}

#[derive(Debug, Serialize, Clone, Copy, Eq, PartialEq)]
pub enum PathType {
    Dir,
    SymlinkDir,
    File,
    SymlinkFile,
}

impl PathType {
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir | Self::SymlinkDir)
    }
}

impl Ord for PathType {
    fn cmp(&self, other: &Self) -> Ordering {
        let to_value = |t: &Self| -> u8 {
            if matches!(t, Self::Dir | Self::SymlinkDir) {
                0
            } else {
                1
            }
        };
        to_value(self).cmp(&to_value(other))
    }
}
impl PartialOrd for PathType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Serialize)]
struct EditData {
    href: String,
    kind: DataKind,
    uri_prefix: String,
    allow_upload: bool,
    allow_delete: bool,
    auth: bool,
    user: Option<String>,
    editable: bool,
}

fn to_timestamp(time: &SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn normalize_path<P: AsRef<Path>>(path: P) -> String {
    let path = path.as_ref().to_str().unwrap_or_default();
    if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.to_string()
    }
}

async fn ensure_path_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if fs::symlink_metadata(parent).await.is_err() {
            fs::create_dir_all(&parent).await?;
        }
    }
    Ok(())
}

fn add_cors(res: &mut Response) {
    res.headers_mut()
        .typed_insert(AccessControlAllowOrigin::ANY);
    // 通配符 Origin 不能与 Allow-Credentials 同时下发（浏览器会直接拒绝该组合）
    res.headers_mut().insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("*"),
    );
    res.headers_mut().insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Authorization,*"),
    );
    res.headers_mut().insert(
        "Access-Control-Expose-Headers",
        HeaderValue::from_static("Authorization,*"),
    );
}

fn res_multistatus(res: &mut Response, content: &str) {
    *res.status_mut() = StatusCode::MULTI_STATUS;
    res.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    *res.body_mut() = body_full(format!(
        r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
{content}
</D:multistatus>"#,
    ));
}

async fn zip_dir<W: AsyncWrite + Unpin>(
    writer: &mut W,
    dir: &Path,
    access_paths: AccessPaths,
    hidden: &[String],
    compression: Compression,
    follow_symlinks: bool,
    serve_path: PathBuf,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let mut writer = ZipFileWriter::with_tokio(writer);
    let hidden = Arc::new(hidden.to_vec());
    let dir_buf = dir.to_path_buf();
    let zip_paths = tokio::task::spawn_blocking(move || {
        collect_dir_entries(
            access_paths,
            running,
            dir_buf,
            hidden,
            follow_symlinks,
            serve_path,
            move |x| {
                // 同时收录文件与目录（保留空目录）。符号链接已由
                // follow_links 解析，file_type 报告的是目标自身的类型。
                x.path().symlink_metadata().is_ok() && {
                    let file_type = x.file_type();
                    file_type.is_file() || file_type.is_dir()
                }
            },
        )
    })
    .await?;
    for zip_path in zip_paths.into_iter() {
        let filename = match zip_path
            .strip_prefix(dir)
            .ok()
            .and_then(|v| v.to_str())
            .map(|v| v.replace(MAIN_SEPARATOR, "/"))
        {
            Some(v) => v,
            None => continue,
        };
        let (datetime, mode) = get_file_mtime_and_mode(&zip_path).await?;
        // 跟随符号链接取元数据，让条目记录的是目标自身的权限和修改时间
        let meta = match tokio::fs::metadata(&zip_path).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        if meta.is_dir() {
            let builder = ZipEntryBuilder::new(format!("{filename}/").into(), compression)
                .unix_permissions(mode)
                .last_modification_date(ZipDateTime::from_chrono(&datetime));
            let mut entry_writer = writer.write_entry_stream(builder).await?.compat_write();
            io::AsyncWriteExt::flush(&mut entry_writer).await?;
            entry_writer.into_inner().close().await?;
        } else {
            let builder = ZipEntryBuilder::new(filename.into(), compression)
                .unix_permissions(mode)
                .last_modification_date(ZipDateTime::from_chrono(&datetime));
            let mut file = File::open(&zip_path).await?;
            let mut file_writer = writer.write_entry_stream(builder).await?.compat_write();
            io::copy(&mut file, &mut file_writer).await?;
            file_writer.into_inner().close().await?;
        }
    }
    writer.close().await?;
    Ok(())
}

fn extract_cache_headers(meta: &Metadata) -> Option<(ETag, LastModified)> {
    let mtime = meta.modified().ok().or_else(|| meta.created().ok())?;
    let timestamp = to_timestamp(&mtime);
    let size = meta.len();
    let etag = format!(r#""{timestamp}-{size}""#).parse::<ETag>().ok()?;
    let last_modified = LastModified::from(mtime);
    Some((etag, last_modified))
}

/// 判断是否为浏览器发起的请求（页面导航、子资源加载、fetch/XHR 都会带 `Sec-Fetch-*`）。
///
/// WebDAV 客户端、curl、rclone 等不会带这些头，据此区分可保证原生认证不受影响。
fn is_browser_request(headers: &hyper::HeaderMap) -> bool {
    headers.contains_key("sec-fetch-mode") || headers.contains_key("sec-fetch-dest")
}

/// 判断是否为浏览器发起的页面导航或子资源加载请求。
///
/// 浏览器在导航（document）和加载图片/脚本/样式/iframe 等子资源时会带上 `Sec-Fetch-Dest`，
/// 这类请求无法附带 `Authorization` 头，若服务器回复 401 挑战，浏览器会弹出原生登录框。
/// 前端 `fetch`/`XMLHttpRequest` 的值为 `empty`，不在返回之列（保留 401 以便前端提示登录）。
fn is_browser_navigation(headers: &hyper::HeaderMap) -> bool {
    matches!(
        headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok()),
        Some("document")
            | Some("image")
            | Some("script")
            | Some("style")
            | Some("font")
            | Some("iframe")
            | Some("frame")
            | Some("audio")
            | Some("video")
            | Some("object")
            | Some("embed")
            | Some("manifest")
            | Some("track")
    )
}

fn status_forbid(res: &mut Response) {
    *res.status_mut() = StatusCode::FORBIDDEN;
    *res.body_mut() = body_full("Forbidden");
}

fn status_not_found(res: &mut Response) {
    *res.status_mut() = StatusCode::NOT_FOUND;
    *res.body_mut() = body_full("Not Found");
}

fn status_no_content(res: &mut Response) {
    *res.status_mut() = StatusCode::NO_CONTENT;
}

fn status_bad_request(res: &mut Response, body: &str) {
    *res.status_mut() = StatusCode::BAD_REQUEST;
    if !body.is_empty() {
        *res.body_mut() = body_full(body.to_string());
    }
}

fn set_content_disposition(res: &mut Response, inline: bool, filename: &str) -> Result<()> {
    let kind = if inline { "inline" } else { "attachment" };
    let filename: String = filename
        .chars()
        .map(|ch| {
            if ch.is_ascii_control() && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect();
    let value = if filename.is_ascii() {
        HeaderValue::from_str(&format!("{kind}; filename=\"{filename}\"",))?
    } else {
        HeaderValue::from_str(&format!(
            "{kind}; filename=\"{}\"; filename*=UTF-8''{}",
            filename,
            encode_uri(&filename),
        ))?
    };
    res.headers_mut().insert(CONTENT_DISPOSITION, value);
    Ok(())
}

/// 从 Cookie 请求头里取出指定名称的值
fn extract_cookie(cookies: &str, name: &str) -> Option<String> {
    cookies.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key.trim() == name).then(|| value.trim().to_string())
    })
}

fn is_hidden(hidden: &[String], file_name: &str, is_dir: bool) -> bool {
    // 账号凭据文件永远不在列表中显示（无论是否通过命令行配置账号、是否刚初始化）
    if file_name == ADMIN_CONFIG_FILE {
        return true;
    }
    hidden.iter().any(|v| {
        if is_dir {
            if let Some(x) = v.strip_suffix('/') {
                return glob(x, file_name);
            }
        }
        glob(v, file_name)
    })
}

fn set_webdav_headers(res: &mut Response) {
    res.headers_mut().insert(
        "Allow",
        HeaderValue::from_static(
            "GET,HEAD,PUT,OPTIONS,DELETE,PATCH,PROPFIND,COPY,MOVE,CHECKAUTH,LOGOUT",
        ),
    );
    res.headers_mut()
        .insert("DAV", HeaderValue::from_static("1, 2, 3"));
}

/// 通过扩展名 + 内容探测判断类型。复用调用方已打开的文件句柄读取前 1KB，
/// 并把游标拨回开头，避免为了嗅探再打开一次文件。
async fn get_content_type(path: &Path, file: &mut File) -> Result<String> {
    let mut buffer = vec![0u8; 1024];
    let n = file.read(&mut buffer).await?;
    buffer.truncate(n);
    file.seek(SeekFrom::Start(0)).await?;
    let mime = mime_guess::from_path(path).first();
    let is_text = content_inspector::inspect(&buffer).is_text();
    let content_type = if is_text {
        let mut detector = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Allow);
        detector.feed(&buffer, buffer.len() < 1024);
        let enc = detector.guess(None, chardetng::Utf8Detection::Allow);
        let charset = format!("; charset={}", enc.name());
        match mime {
            Some(m) => format!("{m}{charset}"),
            None => format!("text/plain{charset}"),
        }
    } else {
        match mime {
            Some(m) => m.to_string(),
            None => "application/octet-stream".into(),
        }
    };
    Ok(content_type)
}

fn parse_upload_offset(headers: &HeaderMap<HeaderValue>, size: u64) -> Result<Option<u64>> {
    let value = match headers.get("x-update-range") {
        Some(v) => v,
        None => return Ok(None),
    };
    let err = || anyhow!("Invalid X-Update-Range Header");
    let value = value.to_str().map_err(|_| err())?;
    if value == "append" {
        return Ok(Some(size));
    }
    // use the first range
    let ranges = parse_range(value, size).ok_or_else(err)?;
    let (start, _) = ranges.first().ok_or_else(err)?;
    Ok(Some(*start))
}

async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn has_query_flag(query_params: &HashMap<String, String>, name: &str) -> bool {
    query_params
        .get(name)
        .map(|v| v.is_empty())
        .unwrap_or_default()
}

/// 同步遍历目录收集条目。调用方必须放在 `spawn_blocking` 里执行：
/// WalkDir 与逐条目的 canonicalize 都是阻塞操作，不能占用异步 worker 线程。
fn collect_dir_entries<F>(
    access_paths: AccessPaths,
    running: Arc<AtomicBool>,
    path: PathBuf,
    hidden: Arc<Vec<String>>,
    follow_symlinks: bool,
    serve_path: PathBuf,
    include_entry: F,
) -> Vec<PathBuf>
where
    F: Fn(&DirEntry) -> bool,
{
    let mut paths: Vec<PathBuf> = vec![];
    for dir in access_paths.entry_paths(&path) {
        let mut it = WalkDir::new(&dir).follow_links(true).into_iter();
        it.next();
        while let Some(entry) = it.next() {
            if !running.load(atomic::Ordering::SeqCst) {
                break;
            }
            let entry = match entry {
                Ok(v) => v,
                Err(_) => continue,
            };
            let entry_path = entry.path();
            let base_name = get_file_name(entry_path);
            let is_dir = entry.file_type().is_dir();
            if is_hidden(&hidden, base_name, is_dir) {
                if is_dir {
                    it.skip_current_dir();
                }
                continue;
            }

            if !follow_symlinks
                && !std::fs::canonicalize(entry_path)
                    .ok()
                    .map(|v| v.starts_with(&serve_path))
                    .unwrap_or_default()
            {
                // We walked outside the server's root. This could only have
                // happened if we followed a symlink, and hence we only allow it
                // if allow_symlink is enabled, otherwise we skip this entry.
                if is_dir {
                    it.skip_current_dir();
                }
                continue;
            }
            if !include_entry(&entry) {
                continue;
            }
            paths.push(entry_path.to_path_buf());
        }
    }
    paths
}
