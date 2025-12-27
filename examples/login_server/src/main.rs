//! 加密登录示例服务器
//!
//! 展示如何使用 rat_web_credential_encryptor 进行安全的登录处理

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Method};
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use rat_web_credential_encryptor::{
    derive_shared_secret, export_public_key, import_public_key,
    decrypt_string, PublicKey, PrivateKey, SharedKey,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

/// 服务器状态，存储会话和密钥
#[derive(Clone)]
struct ServerState {
    /// 服务器密钥对
    server_privkey: Arc<PrivateKey>,
    server_pubkey: Arc<PublicKey>,
    /// 客户端公钥缓存 (session_id -> PublicKey)
    client_keys: Arc<Mutex<HashMap<String, PublicKey>>>,
    /// 派生的共享密钥缓存 (session_id -> SharedKey)
    shared_keys: Arc<Mutex<HashMap<String, SharedKey>>>,
}

/// 请求类型
#[derive(serde::Deserialize)]
struct LoginRequest {
    session_id: String,
    /// Base64 编码的加密数据
    encrypted_data: String,
}

/// 响应类型
#[derive(serde::Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// 公钥响应
#[derive(serde::Serialize)]
struct PubKeyResponse {
    /// Base64 编码的服务器公钥
    server_pubkey: String,
    session_id: String,
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: ServerState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path();

    println!("收到请求: {} {}", method, path);

    match (method.as_str(), path) {
        // 获取服务器公钥
        ("GET", "/api/pubkey") => {
            // 导出服务器公钥
            let pubkey_bytes = export_public_key(&state.server_pubkey);
            let pubkey_b64 = base64ct::Base64::encode_string(&pubkey_bytes);

            // 生成会话 ID
            let session_id = uuid::Uuid::new_v4().to_string();

            let response = PubKeyResponse {
                server_pubkey: pubkey_b64,
                session_id,
            };

            Ok(json_response(ApiResponse {
                success: true,
                data: Some(response),
                error: None,
            }))
        }

        // 提交客户端公钥
        ("POST", "/api/register_client") => {
            let whole_body = req.into_body().collect().await?.to_bytes();
            let data: serde_json::Value = serde_json::from_slice(&whole_body)
                .unwrap_or_else(|_| serde_json::json!({}));

            let session_id = data.get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let client_pubkey_b64 = data.get("client_pubkey")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if session_id.is_empty() || client_pubkey_b64.is_empty() {
                return Ok(json_response(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("缺少参数".into()),
                }));
            }

            // 解码客户端公钥
            let client_pubkey_bytes = match base64ct::Base64::decode_vec(client_pubkey_b64) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Ok(json_response(ApiResponse::<()> {
                        success: false,
                        data: None,
                        error: Some(format!("公钥解码失败: {}", e)),
                    }));
                }
            };

            let client_pubkey = match import_public_key(&client_pubkey_bytes) {
                Ok(key) => key,
                Err(e) => {
                    return Ok(json_response(ApiResponse::<()> {
                        success: false,
                        data: None,
                        error: Some(format!("公钥导入失败: {}", e)),
                    }));
                }
            };

            // 派生共享密钥
            let shared_key = match derive_shared_secret(&state.server_privkey, &client_pubkey) {
                Ok(key) => key,
                Err(e) => {
                    return Ok(json_response(ApiResponse::<()> {
                        success: false,
                        data: None,
                        error: Some(format!("密钥派生失败: {}", e)),
                    }));
                }
            };

            // 存储客户端公钥和共享密钥
            state.client_keys.lock().unwrap().insert(session_id.to_string(), client_pubkey);
            state.shared_keys.lock().unwrap().insert(session_id.to_string(), shared_key);

            Ok(json_response(ApiResponse::<()> {
                success: true,
                data: Some(()),
                error: None,
            }))
        }

        // 登录处理
        ("POST", "/api/login") => {
            let whole_body = req.into_body().collect().await?.to_bytes();
            let data: serde_json::Value = serde_json::from_slice(&whole_body)
                .unwrap_or_else(|_| serde_json::json!({}));

            let session_id = data.get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let encrypted_data = data.get("encrypted_data")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if session_id.is_empty() || encrypted_data.is_empty() {
                return Ok(json_response(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("缺少参数".into()),
                }));
            }

            // 获取共享密钥
            let shared_keys = state.shared_keys.lock().unwrap();
            let shared_key = match shared_keys.get(session_id) {
                Some(key) => key.clone(),
                None => {
                    return Ok(json_response(ApiResponse::<()> {
                        success: false,
                        data: None,
                        error: Some("会话不存在或已过期".into()),
                    }));
                }
            };
            drop(shared_keys);

            // 解密登录数据
            let decrypted = match decrypt_string(encrypted_data, &shared_key) {
                Ok(data) => data,
                Err(e) => {
                    return Ok(json_response(ApiResponse::<()> {
                        success: false,
                        data: None,
                        error: Some(format!("解密失败: {}", e)),
                    }));
                }
            };

            println!("解密后的登录数据: {}", decrypted);

            // 解析登录数据（格式: username:password）
            let parts: Vec<&str> = decrypted.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Ok(json_response(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("数据格式错误".into()),
                }));
            }

            let username = parts[0];
            let password = parts[1];

            // 简单验证：用户名必须至少 3 个字符，密码至少 6 个字符
            let valid = username.len() >= 3 && password.len() >= 6;

            if valid {
                Ok(json_response(ApiResponse::<()> {
                    success: true,
                    data: Some(()),
                    error: None,
                }))
            } else {
                Ok(json_response(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("用户名或密码无效".into()),
                }))
            }
        }

        // 静态文件
        ("GET", _) => {
            let file_path = "examples/static/login.html";

            match tokio::fs::read_to_string(file_path).await {
                Ok(content) => {
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(content)))
                        .unwrap())
                }
                Err(_) => {
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::new(Bytes::from("404 Not Found")))
                        .unwrap())
                }
            }
        }

        _ => {
            Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("Method Not Allowed")))
                .unwrap())
        }
    }
}

fn json_response<T: serde::Serialize>(data: ApiResponse<T>) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(&data).unwrap();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 生成服务器密钥对
    let (server_privkey, server_pubkey) = rat_web_credential_encryptor::generate_keypair();

    println!("加密登录示例服务器");
    println!("===================");
    println!("服务器密钥对已生成");
    println!();

    let state = ServerState {
        server_privkey: Arc::new(server_privkey),
        server_pubkey: Arc::new(server_pubkey),
        client_keys: Arc::new(Mutex::new(HashMap::new())),
        shared_keys: Arc::new(Mutex::new(HashMap::new())),
    };

    let addr: SocketAddr = ([0, 0, 0, 0], 3000).into();
    let listener = TcpListener::bind(addr).await?;
    println!("服务器启动于 http://{}", addr);
    println!("本地浏览器访问: http://127.0.0.1:3000");
    println!("局域网访问: http://<本机IP>:3000");
    println!();

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| handle_request(req, state.clone()));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("连接错误: {}", err);
            }
        });
    }
}
