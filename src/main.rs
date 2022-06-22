use std::net::SocketAddr;

use argon2::Config;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, Executor, SqliteConnection};
use warp::Filter;

lazy_static::lazy_static! {
    static ref TOKEN: String = std::env::var("TOKEN").unwrap();
    static ref DB_URL: String = std::env::var("DB_URL").unwrap();
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistrationRequest {
    username: String,
    password: String,
    token: String,
}

#[tokio::main]
async fn main() {
    let register = warp::path("register")
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .then(|user: RegistrationRequest| async move {
            if user.token != TOKEN.as_str() {
                return warp::reply::with_status(
                    "Invalid token".to_string(),
                    warp::http::StatusCode::UNAUTHORIZED,
                );
            }
            let mut conn = SqliteConnection::connect(&format!("sqlite:{}", DB_URL.as_str()))
                .await
                .unwrap();

            if let Err(err) = conn
                .execute(
                    sqlx::query("INSERT INTO passwords (key, value) VALUES (?1, ?2)")
                        .bind(user.username)
                        .bind(hash(&user.password)),
                )
                .await
            {
                return warp::reply::with_status(
                    format!("{}", err),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                );
            };
            warp::reply::with_status("OK".to_string(), warp::http::StatusCode::OK)
        });
    warp::serve(register)
        .tls()
        .key_path(std::env::var("KEY_PATH").unwrap())
        .cert_path(std::env::var("CERT_PATH").unwrap())
        .run("0.0.0.0:443".parse::<SocketAddr>().unwrap())
        .await;
}

fn hash(password: &str) -> String {
    let mut salt = [0u8; 64];
    rand::rngs::StdRng::from_entropy().fill_bytes(&mut salt);
    let config = Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 64,
        ..Default::default()
    };
    let hashed = argon2::hash_raw(password.as_bytes(), &salt, &config).unwrap();
    format!(
        "argon2:{}:{}:{}:{}:{}",
        config.time_cost,
        config.mem_cost,
        config.lanes,
        base64::encode(salt),
        base64::encode(hashed)
    )
}
