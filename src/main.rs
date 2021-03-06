use std::io::{BufReader, Read};

use actix_web::{post, web, App, HttpResponse, HttpServer};
use argon2::Config;
use rand::{RngCore, SeedableRng};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::certs;
use serde::{Deserialize, Serialize};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};

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
async fn main() -> anyhow::Result<()> {
    HttpServer::new(|| App::new().service(register))
        .bind_rustls("0.0.0.0:443", do_config())?
        .run()
        .await?;
    Ok(())
}

fn do_config() -> rustls::ServerConfig {
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    let cert_file =
        &mut BufReader::new(std::fs::File::open(std::env::var("CERT_PATH").unwrap()).unwrap());
    let key_file =
        &mut BufReader::new(std::fs::File::open(std::env::var("KEY_PATH").unwrap()).unwrap());

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();

    let mut key = Vec::new();
    key_file.read_to_end(&mut key).unwrap();

    config
        .with_single_cert(cert_chain, PrivateKey(key))
        .unwrap()
}

#[post("/register")]
async fn register(user: web::Json<RegistrationRequest>) -> HttpResponse {
    if user.token != TOKEN.as_str() {
        return HttpResponse::Unauthorized().finish();
    }
    let mut file = match OpenOptions::new()
        .append(true)
        .read(true)
        .open(DB_URL.as_str())
        .await
    {
        Ok(file) => file,
        Err(err) => return HttpResponse::InternalServerError().body(format!("{}", err)),
    };

    let line = format!("\n{}:{}", user.username, hash(&user.password));

    if let Err(err) = file.write_all(line.as_bytes()).await {
        return HttpResponse::InternalServerError().body(format!("{}", err));
    };

    HttpResponse::Ok().finish()
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
