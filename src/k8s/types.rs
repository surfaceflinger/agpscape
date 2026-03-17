use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
}

// ── Shared ──

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SeverityCounts {
    pub critical: VulnCounter,
    pub high: VulnCounter,
    pub medium: VulnCounter,
    pub low: VulnCounter,
    pub negligible: VulnCounter,
    pub unknown: VulnCounter,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct VulnCounter {
    pub all: i64,
    pub relevant: i64,
}

/// Simple severity counts (used by config scans — just integers, no all/relevant split)
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SimpleSeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub unknown: i64,
}

#[derive(Debug, Clone)]
pub struct NamespaceSummary {
    pub name: String,
    pub severities: SeverityCounts,
}

/// Workload identity extracted from kubescape.io/* labels
#[derive(Debug, Clone)]
pub struct WorkloadIdentity {
    pub name: String,
    pub kind: String,
    pub workload_name: String,
}

// ── Vulnerabilities ──

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct VulnSummarySpec {
    pub severities: SeverityCounts,
}

#[derive(Debug, Clone)]
pub struct VulnWorkloadSummary {
    pub identity: WorkloadIdentity,
    pub container_name: String,
    pub image_tag: String,
    pub severities: SeverityCounts,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ManifestSpec {
    pub payload: GrypePayload,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct GrypePayload {
    pub matches: Vec<GrypeMatch>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct GrypeMatch {
    pub vulnerability: VulnInfo,
    pub artifact: ArtifactInfo,
    #[serde(rename = "relatedVulnerabilities")]
    pub related_vulnerabilities: Vec<RelatedVuln>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct VulnInfo {
    pub id: String,
    pub severity: String,
    #[serde(rename = "dataSource")]
    pub data_source: String,
    pub fix: FixInfo,
    pub cvss: Option<Vec<CvssEntry>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct CvssEntry {
    pub version: String,
    pub vector: String,
    pub metrics: CvssMetrics,
    pub source: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct CvssMetrics {
    #[serde(rename = "baseScore")]
    pub base_score: f64,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct FixInfo {
    pub versions: Vec<String>,
    pub state: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ArtifactInfo {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub artifact_type: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RelatedVuln {
    pub id: String,
    pub severity: String,
    pub description: String,
}

// ── Configuration Scans ──

#[derive(Debug, Clone)]
pub struct ConfigNamespaceSummary {
    pub name: String,
    pub severities: SimpleSeverityCounts,
}

#[derive(Debug, Clone)]
pub struct ConfigWorkloadSummary {
    pub identity: WorkloadIdentity,
    pub severities: SimpleSeverityCounts,
    pub controls: BTreeMap<String, ConfigControl>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ConfigScanSummarySpec {
    pub severities: SimpleSeverityCounts,
    pub controls: BTreeMap<String, ConfigControl>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ConfigControl {
    #[serde(rename = "controlID")]
    pub control_id: String,
    pub name: String,
    pub severity: ControlSeverity,
    pub status: ControlStatus,
    pub rules: Vec<ConfigRule>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ControlSeverity {
    #[serde(rename = "scoreFactor")]
    pub score_factor: f64,
    pub severity: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ControlStatus {
    pub status: String,
    #[serde(rename = "subStatus")]
    pub sub_status: String,
    pub info: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ConfigRule {
    pub name: String,
    pub status: RuleStatus,
    #[serde(deserialize_with = "null_as_default")]
    pub paths: Vec<FixPath>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RuleStatus {
    pub status: String,
    #[serde(rename = "subStatus")]
    pub sub_status: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct FixPath {
    #[serde(rename = "failedPath")]
    pub failed_path: String,
    #[serde(rename = "fixPath")]
    pub fix_path: String,
    #[serde(rename = "fixPathValue")]
    pub fix_path_value: String,
}

// ── Network Neighborhoods ──

#[derive(Debug, Clone)]
pub struct NetworkNeighborhoodSummary {
    pub identity: WorkloadIdentity,
    pub completion: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct NetworkNeighborhoodSpec {
    #[serde(deserialize_with = "null_as_default")]
    pub containers: Vec<NetworkContainer>,
    #[serde(rename = "initContainers", deserialize_with = "null_as_default")]
    pub init_containers: Vec<NetworkContainer>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct NetworkContainer {
    pub name: String,
    #[serde(deserialize_with = "null_as_default")]
    pub ingress: Vec<NetworkNeighbor>,
    #[serde(deserialize_with = "null_as_default")]
    pub egress: Vec<NetworkNeighbor>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct NetworkNeighbor {
    #[serde(rename = "type")]
    pub neighbor_type: String,
    pub dns: String,
    #[serde(rename = "dnsNames", deserialize_with = "null_as_default")]
    pub dns_names: Vec<String>,
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    pub ports: Vec<NetworkPort>,
    #[serde(rename = "namespaceSelector")]
    pub namespace_selector: Option<LabelSelector>,
    #[serde(rename = "podSelector")]
    pub pod_selector: Option<LabelSelector>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct NetworkPort {
    pub name: String,
    pub port: i64,
    pub protocol: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct LabelSelector {
    #[serde(rename = "matchLabels")]
    pub match_labels: BTreeMap<String, String>,
}

// ── Application Profiles (Runtime) ──

#[derive(Debug, Clone)]
pub struct AppProfileSummary {
    pub identity: WorkloadIdentity,
    pub completion: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AppProfileSpec {
    #[serde(deserialize_with = "null_as_default")]
    pub containers: Vec<AppContainer>,
    #[serde(rename = "initContainers", deserialize_with = "null_as_default")]
    pub init_containers: Vec<AppContainer>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AppContainer {
    pub name: String,
    #[serde(rename = "imageID")]
    pub image_id: String,
    #[serde(rename = "imageTag")]
    pub image_tag: String,
    #[serde(deserialize_with = "null_as_default")]
    pub capabilities: Vec<String>,
    #[serde(deserialize_with = "null_as_default")]
    pub syscalls: Vec<String>,
    #[serde(deserialize_with = "null_as_default")]
    pub opens: Vec<FileOpen>,
    #[serde(deserialize_with = "null_as_default")]
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct FileOpen {
    pub path: String,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Endpoint {
    pub endpoint: String,
    pub methods: Vec<String>,
    pub direction: String,
    pub internal: bool,
}

// ── SBOM ──

#[derive(Debug, Clone)]
pub struct SbomSummary {
    pub name: String,
    pub image_tag: String,
    pub image_id: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SbomSpec {
    pub syft: SyftOutput,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SyftOutput {
    pub artifacts: Vec<SyftArtifact>,
    pub distro: SyftDistro,
    pub source: SyftSource,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SyftArtifact {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub artifact_type: String,
    #[serde(deserialize_with = "null_as_default")]
    pub licenses: Vec<SyftLicense>,
    pub purl: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SyftLicense {
    pub value: String,
    #[serde(rename = "type")]
    pub license_type: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SyftDistro {
    pub name: String,
    pub version: String,
    #[serde(rename = "idLike", deserialize_with = "null_as_default")]
    pub id_like: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SyftSource {
    #[serde(rename = "type")]
    pub source_type: String,
}

// ── Trait impls ──

impl SeverityCounts {
    pub fn total(&self) -> i64 {
        self.critical.all
            + self.high.all
            + self.medium.all
            + self.low.all
            + self.negligible.all
            + self.unknown.all
    }
}

impl ConfigWorkloadSummary {
    pub fn failed_count(&self) -> usize {
        self.controls.values().filter(|c| c.status.status == "failed").count()
    }
    pub fn passed_count(&self) -> usize {
        self.controls.values().filter(|c| c.status.status == "passed").count()
    }
}

impl ConfigScanSummarySpec {
    pub fn failed_controls(&self) -> Vec<&ConfigControl> {
        self.controls.values().filter(|c| c.status.status == "failed").collect()
    }
    pub fn passed_controls(&self) -> Vec<&ConfigControl> {
        self.controls.values().filter(|c| c.status.status == "passed").collect()
    }
    pub fn skipped_controls(&self) -> Vec<&ConfigControl> {
        self.controls.values().filter(|c| c.status.status == "skipped").collect()
    }
}

impl ConfigControl {
    pub fn failed_rules(&self) -> Vec<&ConfigRule> {
        self.rules.iter().filter(|r| r.status.status == "failed").collect()
    }
}

impl SimpleSeverityCounts {
    pub fn total(&self) -> i64 {
        self.critical + self.high + self.medium + self.low + self.unknown
    }
}

impl VulnInfo {
    pub fn cvss_score(&self) -> Option<f64> {
        self.cvss.as_ref()?.iter().map(|c| c.metrics.base_score)
            .reduce(f64::max)
    }

    pub fn cvss_display(&self) -> String {
        match self.cvss_score() {
            Some(s) => format!("{s:.1}"),
            None => String::new(),
        }
    }

    pub fn cvss_class(&self) -> &'static str {
        match self.cvss_score() {
            Some(s) if s >= 9.0 => "critical",
            Some(s) if s >= 7.0 => "high",
            Some(s) if s >= 4.0 => "medium",
            Some(_) => "low",
            None => "",
        }
    }
}

impl GrypeMatch {
    pub fn is_fixable(&self) -> bool {
        !self.vulnerability.fix.versions.is_empty()
    }
}

impl std::ops::AddAssign<&SimpleSeverityCounts> for SimpleSeverityCounts {
    fn add_assign(&mut self, rhs: &SimpleSeverityCounts) {
        self.critical += rhs.critical;
        self.high += rhs.high;
        self.medium += rhs.medium;
        self.low += rhs.low;
        self.unknown += rhs.unknown;
    }
}

// ── Image-level Vulnerability View ──

#[derive(Debug, Clone)]
pub struct ImageVulnSummary {
    pub image_tag: String,
    pub severities: SeverityCounts,
    pub workload_count: usize,
}

// ── Compliance ──

#[derive(Debug, Clone)]
pub struct ComplianceControl {
    pub control_id: String,
    pub name: String,
    pub severity: String,
    pub score_factor: f64,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl ComplianceControl {
    pub fn compliance_pct(&self) -> f64 {
        if self.total == 0 { return 100.0; }
        (self.passed as f64 / self.total as f64) * 100.0
    }

    pub fn compliance_pct_display(&self) -> String {
        format!("{:.0}", self.compliance_pct())
    }

    pub fn framework_tags(&self) -> Vec<&'static str> {
        FRAMEWORKS.iter()
            .filter(|(_, ids)| ids.contains(&self.control_id.as_str()))
            .map(|(name, _)| *name)
            .collect()
    }
}

/// Well-known framework → control ID mappings (subset of most common controls).
/// These are the standard Kubescape framework groupings.
const FRAMEWORKS: &[(&str, &[&str])] = &[
    ("NSA", &[
        "C-0002", "C-0005", "C-0009", "C-0012", "C-0013", "C-0014", "C-0015", "C-0016",
        "C-0017", "C-0018", "C-0019", "C-0020", "C-0021", "C-0030", "C-0034", "C-0035",
        "C-0036", "C-0038", "C-0041", "C-0042", "C-0044", "C-0046", "C-0048", "C-0055",
        "C-0056", "C-0057", "C-0059", "C-0061", "C-0062", "C-0063", "C-0065", "C-0066",
        "C-0067", "C-0068", "C-0069", "C-0073", "C-0075", "C-0077", "C-0078",
    ]),
    ("MITRE", &[
        "C-0001", "C-0002", "C-0004", "C-0005", "C-0007", "C-0012", "C-0014", "C-0015",
        "C-0020", "C-0021", "C-0026", "C-0031", "C-0035", "C-0036", "C-0037", "C-0039",
        "C-0042", "C-0044", "C-0045", "C-0046", "C-0048", "C-0052", "C-0053", "C-0054",
        "C-0057", "C-0058", "C-0059", "C-0066", "C-0067",
    ]),
    ("CIS", &[
        "C-0001", "C-0002", "C-0005", "C-0009", "C-0012", "C-0013", "C-0014", "C-0015",
        "C-0016", "C-0017", "C-0018", "C-0019", "C-0020", "C-0021", "C-0030", "C-0034",
        "C-0035", "C-0038", "C-0041", "C-0042", "C-0044", "C-0046", "C-0048", "C-0055",
        "C-0056", "C-0057", "C-0059", "C-0061", "C-0062", "C-0063", "C-0065", "C-0067",
        "C-0068", "C-0069", "C-0073", "C-0075", "C-0077", "C-0078", "C-0086",
        "C-0198", "C-0199", "C-0200", "C-0206", "C-0207", "C-0208", "C-0209", "C-0210",
        "C-0211", "C-0212",
    ]),
];

// ── Generated Network Policies ──

#[derive(Debug, Clone)]
pub struct GeneratedPolicySummary {
    pub name: String,
    pub namespace: String,
    pub kind: String,
    pub workload: String,
    pub ingress_count: usize,
    pub egress_count: usize,
}

#[derive(Debug, Clone)]
pub struct GeneratedPolicyDetail {
    pub namespace: String,
    pub workload: String,
    pub kind: String,
    pub policy_yaml: String,
}

// ── Known Servers ──

#[derive(Debug, Clone)]
pub struct KnownServerEntry {
    pub name: String,
    pub server: String,
    pub ip_block: String,
}

// ── Runtime Alerts ──

#[derive(Debug, Clone)]
pub struct RuntimeAlert {
    pub timestamp: f64,
    pub message: String,
    pub pod_name: String,
    pub namespace: String,
    pub rule_name: String,
    pub node: String,
}
