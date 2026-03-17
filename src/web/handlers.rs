use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum_htmx::HxRequest;
use std::collections::HashMap;

use super::templates::*;
use crate::error::AppError;
use crate::k8s::queries;
use crate::AppState;

/// Renders the partial template for HTMX requests, or the full page otherwise.
/// The full-page branch clones the data; the partial branch moves it.
macro_rules! htmx_page {
    ($htmx:expr, full: |$($fp:ident),+| $full:expr, partial: $partial:expr) => {
        if $htmx {
            Ok($partial.into_response())
        } else {
            $(let $fp = $fp.clone();)+
            Ok($full.into_response())
        }
    };
}

// ── Home ──

pub async fn home() -> HomeTemplate {
    HomeTemplate {}
}

// ── Vulnerabilities ──

pub async fn vuln_dashboard(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let namespaces = queries::vuln_namespace_summaries(&state.client).await?;
    htmx_page!(htmx,
        full: |namespaces| VulnDashboardTemplate { namespaces },
        partial: VulnDashboardPartial { namespaces }
    )
}

pub async fn vuln_namespace(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path(ns): Path<String>,
) -> Result<Response, AppError> {
    let workloads = queries::vuln_workload_summaries(&state.client, &ns).await?;
    htmx_page!(htmx,
        full: |ns, workloads| VulnNamespaceTemplate { namespace: ns, workloads },
        partial: VulnNamespacePartial { namespace: ns, workloads }
    )
}

pub async fn vuln_workload(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path((ns, summary_name)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let filter = params.get("filter").cloned().unwrap_or_default();
    let workloads = queries::vuln_workload_summaries(&state.client, &ns).await?;
    let workload = workloads
        .into_iter()
        .find(|w| w.identity.name == summary_name)
        .ok_or_else(|| AppError::NotFound(format!("Workload summary '{summary_name}' not found")))?;

    let manifest_name = queries::find_vuln_manifest_name(
        &state.client, &ns,
        &workload.identity.kind, &workload.identity.workload_name, &workload.container_name,
    ).await?.ok_or_else(|| {
        AppError::NotFound(format!("No vulnerability manifest found for {}/{}", workload.identity.workload_name, workload.container_name))
    })?;

    let manifest = queries::vuln_manifest(&state.client, &manifest_name).await?;
    let mut matches = manifest.payload.matches;

    if filter == "fixable" {
        matches.retain(|m| m.is_fixable());
    }

    htmx_page!(htmx,
        full: |ns, workload, matches, filter| VulnWorkloadTemplate { namespace: ns, workload, matches, filter },
        partial: VulnWorkloadPartial { namespace: ns, workload, matches, filter }
    )
}

pub async fn vuln_images(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let images = queries::vuln_image_summaries(&state.client).await?;
    htmx_page!(htmx,
        full: |images| VulnImagesTemplate { images },
        partial: VulnImagesPartial { images }
    )
}

// ── Compliance ──

pub async fn compliance_dashboard(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let controls = queries::compliance_controls(&state.client).await?;
    htmx_page!(htmx,
        full: |controls| ComplianceDashboardTemplate { controls },
        partial: ComplianceDashboardPartial { controls }
    )
}

// ── Configuration ──

pub async fn config_dashboard(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let namespaces = queries::config_namespace_summaries(&state.client).await?;
    htmx_page!(htmx,
        full: |namespaces| ConfigDashboardTemplate { namespaces },
        partial: ConfigDashboardPartial { namespaces }
    )
}

pub async fn config_namespace(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path(ns): Path<String>,
) -> Result<Response, AppError> {
    let workloads = queries::config_workload_summaries(&state.client, &ns).await?;
    htmx_page!(htmx,
        full: |ns, workloads| ConfigNamespaceTemplate { namespace: ns, workloads },
        partial: ConfigNamespacePartial { namespace: ns, workloads }
    )
}

pub async fn config_detail(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let (identity, spec) = queries::config_scan_detail(&state.client, &ns, &name).await?;
    htmx_page!(htmx,
        full: |ns, identity, spec| ConfigDetailTemplate { namespace: ns, identity, spec },
        partial: ConfigDetailPartial { namespace: ns, identity, spec }
    )
}

// ── Network ──

pub async fn network_dashboard(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let namespaces = queries::network_namespace_list(&state.client).await?;
    htmx_page!(htmx,
        full: |namespaces| NetworkDashboardTemplate { namespaces },
        partial: NetworkDashboardPartial { namespaces }
    )
}

pub async fn network_namespace(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path(ns): Path<String>,
) -> Result<Response, AppError> {
    let workloads = queries::network_workload_list(&state.client, &ns).await?;
    htmx_page!(htmx,
        full: |ns, workloads| NetworkNamespaceTemplate { namespace: ns, workloads },
        partial: NetworkNamespacePartial { namespace: ns, workloads }
    )
}

pub async fn network_detail(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let (identity, spec) = queries::network_detail(&state.client, &ns, &name).await?;
    htmx_page!(htmx,
        full: |ns, identity, spec| NetworkDetailTemplate { namespace: ns, identity, spec },
        partial: NetworkDetailPartial { namespace: ns, identity, spec }
    )
}

pub async fn network_policies(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let policies = queries::generated_policies_list(&state.client).await?;
    htmx_page!(htmx,
        full: |policies| NetworkPoliciesTemplate { policies },
        partial: NetworkPoliciesPartial { policies }
    )
}

pub async fn network_policy_detail(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let detail = queries::generated_policy_detail(&state.client, &ns, &name).await?;
    htmx_page!(htmx,
        full: |detail| NetworkPolicyDetailTemplate { detail },
        partial: NetworkPolicyDetailPartial { detail }
    )
}

pub async fn known_servers(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let servers = queries::known_servers_list(&state.client).await?;
    htmx_page!(htmx,
        full: |servers| KnownServersTemplate { servers },
        partial: KnownServersPartial { servers }
    )
}

// ── Runtime ──

pub async fn runtime_dashboard(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let namespaces = queries::runtime_namespace_list(&state.client).await?;
    htmx_page!(htmx,
        full: |namespaces| RuntimeDashboardTemplate { namespaces },
        partial: RuntimeDashboardPartial { namespaces }
    )
}

pub async fn runtime_namespace(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path(ns): Path<String>,
) -> Result<Response, AppError> {
    let workloads = queries::runtime_workload_list(&state.client, &ns).await?;
    htmx_page!(htmx,
        full: |ns, workloads| RuntimeNamespaceTemplate { namespace: ns, workloads },
        partial: RuntimeNamespacePartial { namespace: ns, workloads }
    )
}

pub async fn runtime_detail(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let (identity, spec) = queries::runtime_detail(&state.client, &ns, &name).await?;
    htmx_page!(htmx,
        full: |ns, identity, spec| RuntimeDetailTemplate { namespace: ns, identity, spec },
        partial: RuntimeDetailPartial { namespace: ns, identity, spec }
    )
}

pub async fn runtime_alerts(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let alerts = queries::runtime_alerts(&state.client).await?;
    htmx_page!(htmx,
        full: |alerts| RuntimeAlertsTemplate { alerts },
        partial: RuntimeAlertsPartial { alerts }
    )
}

// ── SBOM ──

pub async fn sbom_dashboard(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let images = queries::sbom_list(&state.client).await?;
    htmx_page!(htmx,
        full: |images| SbomDashboardTemplate { images },
        partial: SbomDashboardPartial { images }
    )
}

pub async fn sbom_detail(
    HxRequest(htmx): HxRequest,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Response, AppError> {
    let (summary, spec) = queries::sbom_detail(&state.client, &name).await?;
    let filtered = queries::sbom_filtered_detail(&state.client, &name).await?;
    htmx_page!(htmx,
        full: |summary, spec, filtered| SbomDetailTemplate { summary, spec, filtered },
        partial: SbomDetailPartial { summary, spec, filtered }
    )
}
