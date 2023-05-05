use super::ConnectionStatus;
use super::{ActivePkg, PkgCache, PkgDir};
use axum::body::StreamBody;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::HeaderMap;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::{Router, Server};
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::{Arc, RwLock};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

struct PkgState {
    dir: PkgDir,
    cache: RwLock<PkgCache>,
    active_pkg_hash: RwLock<Option<String>>,
}

async fn upload(
    headers: HeaderMap,
    State(state): State<Arc<PkgState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let Some(name) = headers.get(super::NAME_HEADER) else {
        return Err((StatusCode::BAD_REQUEST, String::from("required name header")));
    };

    let Some(patch)= headers.get(super::PATCH_HEADER) else {
        return Err((StatusCode::BAD_REQUEST, String::from("required patch header")));
    };

    println!("name: {}", name.to_str().unwrap());
    println!("patch: {}", patch.to_str().unwrap());

    let mut file = match multipart.next_field().await {
        Ok(field) => match field {
            Some(field) => field,
            None => return Err((StatusCode::BAD_REQUEST, String::from("no file provided"))),
        },
        Err(e) => return Err((e.status(), e.body_text())),
    };

    let mut hasher = Sha256::new();

    // should probably write directly to file, but this is easier and
    // works for now
    let mut buffer = Vec::new();
    loop {
        match file.chunk().await {
            Ok(Some(bytes)) => {
                hasher.update(&bytes);
                buffer.extend(bytes);
            }
            Ok(None) => break,
            Err(e) => {
                let text = e.body_text();
                return Err((e.status(), text));
            }
        }
    }

    let hash_string = format!("{:x}", hasher.finalize());

    // if we already have the file, no need to add it
    if state.cache.read().unwrap().contains(&hash_string) {
        return Ok(StatusCode::OK);
    }

    let path = state
        .dir
        .get_pkg_path(&hash_string)
        .expect("hash did not produce valid path");

    let mut file = match File::create(path).await {
        Ok(file) => file,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("could not create file"),
            ))
        }
    };

    if let Err(_) = file.write_all(&buffer).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("could not create file"),
        ));
    }

    // add it to the cache once it is done
    state.cache.write().unwrap().add(hash_string);
    Ok(StatusCode::OK)
}

async fn download(
    State(state): State<Arc<PkgState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let path = match state.dir.get_pkg_path(&hash) {
        Some(path) => path,
        None => return Err((StatusCode::BAD_REQUEST, "Invalid hash provided")),
    };

    let file = match File::open(path).await {
        Ok(file) => file,
        Err(_) => return Err((StatusCode::NOT_FOUND, "Could not open requested package")),
    };

    let stream = ReaderStream::new(file);
    let body = StreamBody::new(stream);

    let headers = [
        (
            header::CONTENT_TYPE,
            String::from("application/octet-stream"),
        ),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", hash),
        ),
        (super::NAME_HEADER, String::from("my_name")),
        (super::PATCH_HEADER, String::from("13.7")),
    ];

    Ok((headers, body))
}

async fn status_check() -> impl IntoResponse {
    Json(ConnectionStatus::Connected)
}

async fn get_active(State(state): State<Arc<PkgState>>) -> impl IntoResponse {
    let active = match state.active_pkg_hash.read().unwrap().as_deref() {
        Some(hash) => Some(hash.to_owned()),
        None => None,
    };

    Json(ActivePkg { hash: active })
}

async fn list(State(state): State<Arc<PkgState>>) -> impl IntoResponse {
    let hashes: Vec<String> = state
        .cache
        .read()
        .unwrap()
        .hashes()
        .map(|hash| String::from(hash))
        .collect();

    Json(hashes)
}

async fn activate(
    State(state): State<Arc<PkgState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    if state.cache.read().unwrap().contains(&hash) == false {
        return Err((StatusCode::BAD_REQUEST, "package does not exist"));
    }
    *state.active_pkg_hash.write().unwrap() = Some(hash);

    Ok(StatusCode::OK)
}

async fn deactivate(
    State(state): State<Arc<PkgState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    if state.cache.read().unwrap().contains(&hash) == false {
        return Err((StatusCode::BAD_REQUEST, "package does not exist"));
    }

    // deactivate the package if it is the active one
    let mut hash_ref = state.active_pkg_hash.write().unwrap();
    match hash_ref.as_deref() {
        Some(active_hash) if active_hash == &hash => {
            *hash_ref = None;
        }
        _ => return Err((StatusCode::CONFLICT, "package not active")),
    }

    Ok(StatusCode::OK)
}

pub async fn listen(dir: PkgDir, cache: PkgCache, port: u16) {
    let router = Router::new()
        .route("/status", get(status_check))
        .route("/get-active", get(get_active))
        .route("/upload", post(upload))
        .route("/list", get(list))
        .route("/download/:hash", get(download))
        .route("/activate/:hash", post(activate))
        .route("/deactivate/:hash", post(deactivate))
        .with_state(Arc::new(PkgState {
            dir,
            cache: RwLock::new(cache),
            active_pkg_hash: RwLock::new(None),
        }))
        .layer(DefaultBodyLimit::max(1024 * 1024 * 50)); // 10mb max file size

    let addr: SocketAddrV4 = format!("127.0.0.1:{}", port).parse().unwrap();
    Server::bind(&SocketAddr::V4(addr))
        .serve(router.into_make_service())
        .await
        .unwrap();
}
