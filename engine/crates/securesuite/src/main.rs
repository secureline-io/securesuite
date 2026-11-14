//! SecureSuite engine entrypoint: starts the intercepting proxy and the local
//! web UI/API, sharing one in-memory exchange store.

mod active;
mod comparer;
mod model;
mod proxy;
mod rules;
mod scan;
mod sequencer;
mod store;
mod web;
mod wscap;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::Proxy;

use proxy::Recorder;
use store::Store;
use web::WebState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install a process-wide rustls crypto provider (used by the MITM TLS stack).
    let _ = aws_lc_rs::default_provider().install_default();

    // Ports are configurable (env) so SecureSuite can coexist with other proxies
    // such as Burp on its default 8080.
    let proxy_port: u16 = std::env::var("SECURESUITE_PROXY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);
    let ui_port: u16 = std::env::var("SECURESUITE_UI_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8081);
    let oast_port: u16 = std::env::var("SECURESUITE_OAST_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8082);
    let proxy_addr: SocketAddr = ([127, 0, 0, 1], proxy_port).into();
    let ui_addr: SocketAddr = ([127, 0, 0, 1], ui_port).into();
    let oast_addr: SocketAddr = ([127, 0, 0, 1], oast_port).into();

    // Persistent CA (stable across restarts; private key written 0600).
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let data_dir = PathBuf::from(home).join(".securesuite");
    let (ca_cert_pem, ca_key_pem) = load_or_make_ca(&data_dir)?;

    let key_pair = KeyPair::from_pem(&ca_key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, key_pair)?;
    let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

    let store = Arc::new(Store::with_db(Some(&data_dir.join("history.db"))));

    // Web UI/API server (loopback).
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        // A silent target must not hang Repeater or pin an Intruder/Discover slot.
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    web::spawn_extension_dispatcher(store.clone(), client.clone());
    let app = web::router(WebState {
        store: store.clone(),
        ca_pem: ca_cert_pem.clone(),
        client,
        proxy_port,
        oast_port,
    });
    let listener = tokio::net::TcpListener::bind(ui_addr).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app.into_make_service()).await {
            eprintln!("[ui] server error: {e}");
        }
    });

    // OAST canary listener (records out-of-band callbacks).
    let oast_app = web::oast_router(store.clone());
    let oast_listener = tokio::net::TcpListener::bind(oast_addr).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            oast_listener,
            oast_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            eprintln!("[oast] server error: {e}");
        }
    });

    // Intercepting proxy.
    let proxy = Proxy::builder()
        .with_addr(proxy_addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(Recorder::new(store.clone()))
        .with_websocket_handler(wscap::WsRecorder::new(store))
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build proxy: {e}"))?;

    println!("SecureSuite engine running:");
    println!("  • Proxy : http://{proxy_addr}   (set this as your HTTP & HTTPS proxy)");
    println!("  • Web UI: http://{ui_addr}");
    println!(
        "  • CA    : {}/ca-cert.pem   (trust this to intercept HTTPS; or GET /api/ca.pem)",
        data_dir.display()
    );
    println!("  • OAST  : http://{oast_addr}/<token>   (out-of-band canary listener)");
    println!("Press Ctrl+C to stop. Authorized testing only.");

    proxy.start().await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Load the persisted CA, or create and persist a new "SecureSuite CA".
fn load_or_make_ca(dir: &Path) -> anyhow::Result<(String, String)> {
    let cert_path = dir.join("ca-cert.pem");
    let key_path = dir.join("ca-key.pem");
    if cert_path.exists() && key_path.exists() {
        return Ok((
            std::fs::read_to_string(&cert_path)?,
            std::fs::read_to_string(&key_path)?,
        ));
    }

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "SecureSuite CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "SecureSuite");
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2034, 1, 1);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    std::fs::create_dir_all(dir)?;
    std::fs::write(&cert_path, &cert_pem)?;
    write_private(&key_path, &key_pem)?;
    Ok((cert_pem, key_pem))
}

#[cfg(unix)]
fn write_private(path: &Path, data: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data.as_bytes())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &str) -> std::io::Result<()> {
    std::fs::write(path, data)
}
