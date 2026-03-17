mod error;
mod k8s;
mod web;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    pub client: kube::Client,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let client = kube::Client::try_default().await?;
    tracing::info!("connected to Kubernetes cluster");

    let state = AppState { client };
    let app = web::routes::router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tracing::info!(%addr, "starting server");

    let url = format!("http://{addr}");
    if let Err(e) = open::that(&url) {
        tracing::warn!("could not open browser: {e}");
    }

    axum::serve(listener, app).await?;

    Ok(())
}
