use askama::Template;
use axum::response::{Html, IntoResponse, Response};

use crate::error::AppError;
use crate::k8s::types::*;

macro_rules! impl_template_response {
    ($($t:ty),* $(,)?) => {
        $(
            impl IntoResponse for $t {
                fn into_response(self) -> Response {
                    match self.render() {
                        Ok(html) => Html(html).into_response(),
                        Err(e) => AppError::from(e).into_response(),
                    }
                }
            }
        )*
    };
}

// ── Home ──

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct HomeTemplate {}

// ── Vulnerabilities ──

#[derive(Template)]
#[template(path = "vuln/dashboard.html")]
pub struct VulnDashboardTemplate {
    pub namespaces: Vec<NamespaceSummary>,
}

#[derive(Template)]
#[template(path = "vuln/content.html")]
pub struct VulnDashboardPartial {
    pub namespaces: Vec<NamespaceSummary>,
}

#[derive(Template)]
#[template(path = "vuln/namespace.html")]
pub struct VulnNamespaceTemplate {
    pub namespace: String,
    pub workloads: Vec<VulnWorkloadSummary>,
}

#[derive(Template)]
#[template(path = "vuln/namespace_content.html")]
pub struct VulnNamespacePartial {
    pub namespace: String,
    pub workloads: Vec<VulnWorkloadSummary>,
}

#[derive(Template)]
#[template(path = "vuln/workload.html")]
pub struct VulnWorkloadTemplate {
    pub namespace: String,
    pub workload: VulnWorkloadSummary,
    pub matches: Vec<GrypeMatch>,
    pub filter: String,
}

#[derive(Template)]
#[template(path = "vuln/workload_content.html")]
pub struct VulnWorkloadPartial {
    pub namespace: String,
    pub workload: VulnWorkloadSummary,
    pub matches: Vec<GrypeMatch>,
    pub filter: String,
}

#[derive(Template)]
#[template(path = "vuln/images.html")]
pub struct VulnImagesTemplate {
    pub images: Vec<ImageVulnSummary>,
}

#[derive(Template)]
#[template(path = "vuln/images_content.html")]
pub struct VulnImagesPartial {
    pub images: Vec<ImageVulnSummary>,
}

// ── Compliance ──

#[derive(Template)]
#[template(path = "compliance/dashboard.html")]
pub struct ComplianceDashboardTemplate {
    pub controls: Vec<ComplianceControl>,
}

#[derive(Template)]
#[template(path = "compliance/content.html")]
pub struct ComplianceDashboardPartial {
    pub controls: Vec<ComplianceControl>,
}

// ── Configuration ──

#[derive(Template)]
#[template(path = "config/dashboard.html")]
pub struct ConfigDashboardTemplate {
    pub namespaces: Vec<ConfigNamespaceSummary>,
}

#[derive(Template)]
#[template(path = "config/content.html")]
pub struct ConfigDashboardPartial {
    pub namespaces: Vec<ConfigNamespaceSummary>,
}

#[derive(Template)]
#[template(path = "config/namespace.html")]
pub struct ConfigNamespaceTemplate {
    pub namespace: String,
    pub workloads: Vec<ConfigWorkloadSummary>,
}

#[derive(Template)]
#[template(path = "config/namespace_content.html")]
pub struct ConfigNamespacePartial {
    pub namespace: String,
    pub workloads: Vec<ConfigWorkloadSummary>,
}

#[derive(Template)]
#[template(path = "config/detail.html")]
pub struct ConfigDetailTemplate {
    pub namespace: String,
    pub identity: WorkloadIdentity,
    pub spec: ConfigScanSummarySpec,
}

#[derive(Template)]
#[template(path = "config/detail_content.html")]
pub struct ConfigDetailPartial {
    pub namespace: String,
    pub identity: WorkloadIdentity,
    pub spec: ConfigScanSummarySpec,
}

// ── Network ──

#[derive(Template)]
#[template(path = "network/dashboard.html")]
pub struct NetworkDashboardTemplate {
    pub namespaces: Vec<(String, usize)>,
}

#[derive(Template)]
#[template(path = "network/content.html")]
pub struct NetworkDashboardPartial {
    pub namespaces: Vec<(String, usize)>,
}

#[derive(Template)]
#[template(path = "network/namespace.html")]
pub struct NetworkNamespaceTemplate {
    pub namespace: String,
    pub workloads: Vec<NetworkNeighborhoodSummary>,
}

#[derive(Template)]
#[template(path = "network/namespace_content.html")]
pub struct NetworkNamespacePartial {
    pub namespace: String,
    pub workloads: Vec<NetworkNeighborhoodSummary>,
}

#[derive(Template)]
#[template(path = "network/detail.html")]
pub struct NetworkDetailTemplate {
    pub namespace: String,
    pub identity: WorkloadIdentity,
    pub spec: NetworkNeighborhoodSpec,
}

#[derive(Template)]
#[template(path = "network/detail_content.html")]
pub struct NetworkDetailPartial {
    pub namespace: String,
    pub identity: WorkloadIdentity,
    pub spec: NetworkNeighborhoodSpec,
}

#[derive(Template)]
#[template(path = "network/policies.html")]
pub struct NetworkPoliciesTemplate {
    pub policies: Vec<GeneratedPolicySummary>,
}

#[derive(Template)]
#[template(path = "network/policies_content.html")]
pub struct NetworkPoliciesPartial {
    pub policies: Vec<GeneratedPolicySummary>,
}

#[derive(Template)]
#[template(path = "network/policy_detail.html")]
pub struct NetworkPolicyDetailTemplate {
    pub detail: GeneratedPolicyDetail,
}

#[derive(Template)]
#[template(path = "network/policy_detail_content.html")]
pub struct NetworkPolicyDetailPartial {
    pub detail: GeneratedPolicyDetail,
}

#[derive(Template)]
#[template(path = "network/servers.html")]
pub struct KnownServersTemplate {
    pub servers: Vec<KnownServerEntry>,
}

#[derive(Template)]
#[template(path = "network/servers_content.html")]
pub struct KnownServersPartial {
    pub servers: Vec<KnownServerEntry>,
}

// ── Runtime ──

#[derive(Template)]
#[template(path = "runtime/dashboard.html")]
pub struct RuntimeDashboardTemplate {
    pub namespaces: Vec<(String, usize)>,
}

#[derive(Template)]
#[template(path = "runtime/content.html")]
pub struct RuntimeDashboardPartial {
    pub namespaces: Vec<(String, usize)>,
}

#[derive(Template)]
#[template(path = "runtime/namespace.html")]
pub struct RuntimeNamespaceTemplate {
    pub namespace: String,
    pub workloads: Vec<AppProfileSummary>,
}

#[derive(Template)]
#[template(path = "runtime/namespace_content.html")]
pub struct RuntimeNamespacePartial {
    pub namespace: String,
    pub workloads: Vec<AppProfileSummary>,
}

#[derive(Template)]
#[template(path = "runtime/detail.html")]
pub struct RuntimeDetailTemplate {
    pub namespace: String,
    pub identity: WorkloadIdentity,
    pub spec: AppProfileSpec,
}

#[derive(Template)]
#[template(path = "runtime/detail_content.html")]
pub struct RuntimeDetailPartial {
    pub namespace: String,
    pub identity: WorkloadIdentity,
    pub spec: AppProfileSpec,
}

#[derive(Template)]
#[template(path = "runtime/alerts.html")]
pub struct RuntimeAlertsTemplate {
    pub alerts: Vec<RuntimeAlert>,
}

#[derive(Template)]
#[template(path = "runtime/alerts_content.html")]
pub struct RuntimeAlertsPartial {
    pub alerts: Vec<RuntimeAlert>,
}

// ── SBOM ──

#[derive(Template)]
#[template(path = "sbom/dashboard.html")]
pub struct SbomDashboardTemplate {
    pub images: Vec<SbomSummary>,
}

#[derive(Template)]
#[template(path = "sbom/content.html")]
pub struct SbomDashboardPartial {
    pub images: Vec<SbomSummary>,
}

#[derive(Template)]
#[template(path = "sbom/detail.html")]
pub struct SbomDetailTemplate {
    pub summary: SbomSummary,
    pub spec: SbomSpec,
    pub filtered: Option<SbomSpec>,
}

#[derive(Template)]
#[template(path = "sbom/detail_content.html")]
pub struct SbomDetailPartial {
    pub summary: SbomSummary,
    pub spec: SbomSpec,
    pub filtered: Option<SbomSpec>,
}

impl_template_response!(
    HomeTemplate,
    VulnDashboardTemplate, VulnDashboardPartial,
    VulnNamespaceTemplate, VulnNamespacePartial,
    VulnWorkloadTemplate, VulnWorkloadPartial,
    VulnImagesTemplate, VulnImagesPartial,
    ComplianceDashboardTemplate, ComplianceDashboardPartial,
    ConfigDashboardTemplate, ConfigDashboardPartial,
    ConfigNamespaceTemplate, ConfigNamespacePartial,
    ConfigDetailTemplate, ConfigDetailPartial,
    NetworkDashboardTemplate, NetworkDashboardPartial,
    NetworkNamespaceTemplate, NetworkNamespacePartial,
    NetworkDetailTemplate, NetworkDetailPartial,
    NetworkPoliciesTemplate, NetworkPoliciesPartial,
    NetworkPolicyDetailTemplate, NetworkPolicyDetailPartial,
    KnownServersTemplate, KnownServersPartial,
    RuntimeDashboardTemplate, RuntimeDashboardPartial,
    RuntimeNamespaceTemplate, RuntimeNamespacePartial,
    RuntimeDetailTemplate, RuntimeDetailPartial,
    RuntimeAlertsTemplate, RuntimeAlertsPartial,
    SbomDashboardTemplate, SbomDashboardPartial,
    SbomDetailTemplate, SbomDetailPartial,
);
