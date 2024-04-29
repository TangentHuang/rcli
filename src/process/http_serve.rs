use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::routing::get;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on port {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    let dir_service = ServeDir::new(path)
        .append_index_html_on_directories(true)
        .precompressed_gzip()
        .precompressed_br()
        .precompressed_zstd()
        .precompressed_deflate();

    let router = axum::Router::new()
        .nest_service("/tower", dir_service)
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, router).await.unwrap();
    Ok(())
}
async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, [(header::HeaderName, &'static str); 1], String) {
    let path_name = path.clone();
    let p = std::path::Path::new(&state.path).join(path.clone());
    info!("Reading file {:?}", p);
    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain")],
            format!("File: {} not found!", &p.display()),
        )
    } else if p.is_dir() {
        info!("List directory: {:?}", p);
        let mut reader = tokio::fs::read_dir(p).await.unwrap();
        let mut content = String::new();
        while let Some(entry) = reader.next_entry().await.unwrap() {
            let file_name = entry.file_name();
            let file_name = file_name.into_string().unwrap();
            let file_type = entry.file_type().await.unwrap();
            let file_name_url = urlencoding::encode(&file_name);
            if file_type.is_dir() {
                content.push_str(
                    format!("<li><a href=\"{}/\">{}/</a></li>", file_name_url, file_name).as_ref(),
                );
            } else {
                content.push_str(
                    format!("<li><a href=\"{}\">{}</a></li>", file_name_url, file_name).as_ref(),
                );
            }
        }
        let html_content = format!(
            r#"<html lang="en">
            <head>
                <meta charset="utf-8">
                <title>Rcli static files server</title>
            </head>
            <body>
                <h1>Directory listing for {}</h1>
                <hr>
                <ul>
                    {}
                </ul>
                <hr>
            </body>
            </html>"#,
            path_name, content
        );
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html")],
            format!("<html><body><ul>{}</ul></body></html>", html_content),
        )
    } else {
        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/plain")],
                    content,
                )
            }
            Err(e) => {
                warn!("Error reading file:{:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, "text/plain")],
                    format!("Error reading file:{}", e),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = HttpServeState {
            path: PathBuf::from("./tests/http_test"),
        };
        let (status_code, _, _) =
            file_handler(State(Arc::new(state)), Path("test.rest".to_string())).await;
        assert_eq!(status_code, StatusCode::OK);
    }
}
