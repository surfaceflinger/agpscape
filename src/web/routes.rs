use axum::routing::get;
use axum::Router;
use tower_http::services::ServeDir;

use super::handlers;
use crate::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handlers::home))
        // Vulnerabilities
        .route("/vuln", get(handlers::vuln_dashboard))
        .route("/vuln/images", get(handlers::vuln_images))
        .route("/vuln/ns/{ns}", get(handlers::vuln_namespace))
        .route("/vuln/ns/{ns}/workload/{name}", get(handlers::vuln_workload))
        // Compliance
        .route("/compliance", get(handlers::compliance_dashboard))
        // Configuration
        .route("/config", get(handlers::config_dashboard))
        .route("/config/ns/{ns}", get(handlers::config_namespace))
        .route("/config/ns/{ns}/resource/{name}", get(handlers::config_detail))
        // Network
        .route("/network", get(handlers::network_dashboard))
        .route("/network/ns/{ns}", get(handlers::network_namespace))
        .route("/network/ns/{ns}/workload/{name}", get(handlers::network_detail))
        .route("/network/policies", get(handlers::network_policies))
        .route("/network/policies/ns/{ns}/{name}", get(handlers::network_policy_detail))
        .route("/network/servers", get(handlers::known_servers))
        // Runtime
        .route("/runtime", get(handlers::runtime_dashboard))
        .route("/runtime/alerts", get(handlers::runtime_alerts))
        .route("/runtime/ns/{ns}", get(handlers::runtime_namespace))
        .route("/runtime/ns/{ns}/workload/{name}", get(handlers::runtime_detail))
        // SBOM
        .route("/sbom", get(handlers::sbom_dashboard))
        .route("/sbom/image/{name}", get(handlers::sbom_detail))
        // Static
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state)
}
