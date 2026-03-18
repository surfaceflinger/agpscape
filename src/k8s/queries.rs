use std::collections::BTreeMap;

use backon::{ExponentialBuilder, Retryable};
use kube::api::{Api, DynamicObject, ListParams};
use kube::Client;

use super::resources;
use super::types::*;
use crate::error::AppError;

// ── Helpers ──

fn full_spec_params() -> ListParams {
    ListParams {
        resource_version: Some("fullSpec".into()),
        ..Default::default()
    }
}

fn is_retryable(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(resp) if resp.code == 429 || resp.code >= 500)
}

fn retry_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(std::time::Duration::from_millis(250))
        .with_max_times(4)
}

async fn get_retry(api: &Api<DynamicObject>, name: &str) -> Result<DynamicObject, kube::Error> {
    let name = name.to_string();
    let api = api.clone();
    (|| async { api.get(&name).await })
        .retry(retry_backoff())
        .when(is_retryable)
        .notify(|e, dur| tracing::warn!(?dur, "retrying get after {e}"))
        .await
}

async fn list_retry(
    api: &Api<DynamicObject>,
    lp: &ListParams,
) -> Result<kube::api::ObjectList<DynamicObject>, kube::Error> {
    let api = api.clone();
    let lp = lp.clone();
    (|| async { api.list(&lp).await })
        .retry(retry_backoff())
        .when(is_retryable)
        .notify(|e, dur| tracing::warn!(?dur, "retrying list after {e}"))
        .await
}

/// List with full spec data (Kubescape aggregated API feature).
async fn list_full(api: &Api<DynamicObject>) -> Result<Vec<DynamicObject>, AppError> {
    Ok(list_retry(api, &full_spec_params()).await?.items)
}

fn extract_identity(obj: &DynamicObject) -> Option<WorkloadIdentity> {
    let labels = obj.metadata.labels.as_ref()?;
    Some(WorkloadIdentity {
        name: obj.metadata.name.clone()?,
        kind: labels.get("kubescape.io/workload-kind").cloned().unwrap_or_default(),
        workload_name: labels.get("kubescape.io/workload-name").cloned().unwrap_or_default(),
    })
}

fn label(obj: &DynamicObject, key: &str) -> String {
    obj.metadata.labels.as_ref()
        .and_then(|l| l.get(key))
        .cloned()
        .unwrap_or_default()
}

fn annotation(obj: &DynamicObject, key: &str) -> String {
    obj.metadata.annotations.as_ref()
        .and_then(|a| a.get(key))
        .cloned()
        .unwrap_or_default()
}

fn group_by_ns(items: &[DynamicObject]) -> BTreeMap<String, Vec<&DynamicObject>> {
    let mut m: BTreeMap<String, Vec<&DynamicObject>> = BTreeMap::new();
    for obj in items {
        let ns = obj.metadata.namespace.clone().unwrap_or_default();
        m.entry(ns).or_default().push(obj);
    }
    m
}

fn parse_spec<T: serde::de::DeserializeOwned>(obj: &DynamicObject) -> Option<T> {
    serde_json::from_value(obj.data.get("spec")?.clone()).ok()
}


// ── Vulnerabilities ──

pub async fn vuln_namespace_summaries(client: &Client) -> Result<Vec<NamespaceSummary>, AppError> {
    // Use the cluster-scoped VulnerabilitySummary (one per namespace) instead
    // of listing all per-workload summaries and grouping manually.
    let api = Api::all_with(client.clone(), &resources::vulnerability_summary());
    let items = list_full(&api).await?;

    let mut out: Vec<NamespaceSummary> = items
        .into_iter()
        .filter_map(|obj| {
            let name = obj.metadata.name.clone()?;
            let spec = parse_spec::<VulnNamespaceSummarySpec>(&obj)?;
            Some(NamespaceSummary { name, severities: spec.severities })
        })
        .collect();
    out.sort_by(|a, b| {
        b.severities.critical.all.cmp(&a.severities.critical.all)
            .then(b.severities.high.all.cmp(&a.severities.high.all))
            .then(a.name.cmp(&b.name))
    });
    Ok(out)
}

pub async fn vuln_workload_summaries(
    client: &Client,
    namespace: &str,
) -> Result<Vec<VulnWorkloadSummary>, AppError> {
    let api = Api::namespaced_with(client.clone(), namespace, &resources::vulnerability_manifest_summary());
    let items = list_full(&api).await?;

    let mut summaries: Vec<VulnWorkloadSummary> = items
        .into_iter()
        .filter_map(|obj| {
            let identity = extract_identity(&obj)?;
            let spec = parse_spec::<VulnManifestSummarySpec>(&obj)?;
            Some(VulnWorkloadSummary {
                container_name: label(&obj, "kubescape.io/workload-container-name"),
                image_tag: annotation(&obj, "kubescape.io/image-tag"),
                manifest_name: spec.vulnerabilities_ref.all.name,
                severities: spec.severities,
                identity,
            })
        })
        .collect();
    summaries.sort_by(|a, b| {
        b.severities.critical.all.cmp(&a.severities.critical.all)
            .then(b.severities.high.all.cmp(&a.severities.high.all))
            .then(a.identity.workload_name.cmp(&b.identity.workload_name))
    });
    Ok(summaries)
}

/// Fetch vulnerability matches by manifest name.
///
/// The manifest name comes from `VulnerabilityManifestSummary.spec.vulnerabilitiesRef.all.name`
/// which points to the image-scoped VulnerabilityManifest containing all CVE matches.
/// We use a fullSpec list (the aggregated API ignores field selectors) and find by name.
pub async fn vuln_manifest(client: &Client, name: &str) -> Result<ManifestSpec, AppError> {
    let api = Api::namespaced_with(client.clone(), "kubescape", &resources::vulnerability_manifest());
    let full_items = list_full(&api).await?;
    let obj = full_items.into_iter()
        .find(|o| o.metadata.name.as_deref() == Some(name))
        .ok_or_else(|| AppError::NotFound(format!(
            "Vulnerability manifest '{name}' not found"
        )))?;
    Ok(serde_json::from_value(obj.data.get("spec").cloned().unwrap_or_default())?)
}

/// Aggregate vulnerabilities by image across all workloads.
pub async fn vuln_image_summaries(client: &Client) -> Result<Vec<ImageVulnSummary>, AppError> {
    let api = Api::all_with(client.clone(), &resources::vulnerability_manifest_summary());
    let items = list_full(&api).await?;

    let mut by_image: BTreeMap<String, ImageVulnSummary> = BTreeMap::new();
    for obj in &items {
        let image_tag = annotation(obj, "kubescape.io/image-tag");
        if image_tag.is_empty() { continue; }
        let spec = match parse_spec::<VulnManifestSummarySpec>(obj) {
            Some(s) => s,
            None => continue,
        };
        let entry = by_image.entry(image_tag.clone()).or_insert_with(|| ImageVulnSummary {
            image_tag: image_tag.clone(),
            severities: SeverityCounts::default(),
            workload_count: 0,
        });
        // Take the max severities per image (same image = same vulns)
        entry.severities.critical.all = entry.severities.critical.all.max(spec.severities.critical.all);
        entry.severities.high.all = entry.severities.high.all.max(spec.severities.high.all);
        entry.severities.medium.all = entry.severities.medium.all.max(spec.severities.medium.all);
        entry.severities.low.all = entry.severities.low.all.max(spec.severities.low.all);
        entry.severities.negligible.all = entry.severities.negligible.all.max(spec.severities.negligible.all);
        entry.severities.unknown.all = entry.severities.unknown.all.max(spec.severities.unknown.all);
        entry.severities.critical.relevant = entry.severities.critical.relevant.max(spec.severities.critical.relevant);
        entry.severities.high.relevant = entry.severities.high.relevant.max(spec.severities.high.relevant);
        entry.severities.medium.relevant = entry.severities.medium.relevant.max(spec.severities.medium.relevant);
        entry.severities.low.relevant = entry.severities.low.relevant.max(spec.severities.low.relevant);
        entry.severities.negligible.relevant = entry.severities.negligible.relevant.max(spec.severities.negligible.relevant);
        entry.severities.unknown.relevant = entry.severities.unknown.relevant.max(spec.severities.unknown.relevant);
        entry.workload_count += 1;
    }

    let mut out: Vec<ImageVulnSummary> = by_image.into_values().collect();
    out.sort_by(|a, b| {
        b.severities.critical.all.cmp(&a.severities.critical.all)
            .then(b.severities.high.all.cmp(&a.severities.high.all))
            .then(a.image_tag.cmp(&b.image_tag))
    });
    Ok(out)
}

// ── Configuration Scans ──

pub async fn config_namespace_summaries(
    client: &Client,
) -> Result<Vec<ConfigNamespaceSummary>, AppError> {
    let api = Api::all_with(client.clone(), &resources::workload_configuration_scan_summary());
    let items = list_full(&api).await?;
    let grouped = group_by_ns(&items);

    let mut out: Vec<ConfigNamespaceSummary> = grouped
        .into_iter()
        .map(|(ns, objs)| {
            let mut sev = SimpleSeverityCounts::default();
            for obj in objs {
                if let Some(spec) = parse_spec::<ConfigScanSummarySpec>(obj) {
                    sev += &spec.severities;
                }
            }
            ConfigNamespaceSummary { name: ns, severities: sev }
        })
        .collect();
    out.sort_by(|a, b| {
        b.severities.critical.cmp(&a.severities.critical)
            .then(b.severities.high.cmp(&a.severities.high))
            .then(a.name.cmp(&b.name))
    });
    Ok(out)
}

pub async fn config_workload_summaries(
    client: &Client,
    namespace: &str,
) -> Result<Vec<ConfigWorkloadSummary>, AppError> {
    let api = Api::namespaced_with(client.clone(), namespace, &resources::workload_configuration_scan_summary());
    let items = list_full(&api).await?;

    let mut summaries: Vec<ConfigWorkloadSummary> = items
        .into_iter()
        .filter_map(|obj| {
            let identity = extract_identity(&obj)?;
            let spec = parse_spec::<ConfigScanSummarySpec>(&obj)?;
            Some(ConfigWorkloadSummary {
                identity,
                severities: spec.severities,
                controls: spec.controls,
            })
        })
        .collect();
    summaries.sort_by(|a, b| {
        b.severities.critical.cmp(&a.severities.critical)
            .then(b.severities.high.cmp(&a.severities.high))
            .then(a.identity.workload_name.cmp(&b.identity.workload_name))
    });
    Ok(summaries)
}

pub async fn config_scan_detail(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<(WorkloadIdentity, ConfigScanSummarySpec), AppError> {
    let api = Api::namespaced_with(client.clone(), namespace, &resources::workload_configuration_scan());
    let obj = get_retry(&api, name).await?;
    let identity = extract_identity(&obj)
        .ok_or_else(|| AppError::NotFound(format!("Missing identity for {name}")))?;
    let spec: ConfigScanSummarySpec = serde_json::from_value(obj.data.get("spec").cloned().unwrap_or_default())?;
    Ok((identity, spec))
}

/// Get all controls across all workloads, grouped by control ID, for compliance view.
pub async fn compliance_controls(client: &Client) -> Result<Vec<ComplianceControl>, AppError> {
    let summary_api = Api::all_with(client.clone(), &resources::workload_configuration_scan_summary());
    let scan_api = Api::all_with(client.clone(), &resources::workload_configuration_scan());

    // Fetch summaries (for pass/fail counts) and full scans (for control names).
    // Each scan only covers ~1 control, so we need all scans to collect all 92+ names.
    let (summary_items, scan_items) = tokio::try_join!(
        list_full(&summary_api),
        list_full(&scan_api),
    )?;

    // Build control ID → name lookup from full scans
    let mut name_lookup: BTreeMap<String, String> = BTreeMap::new();
    for obj in &scan_items {
        if let Some(spec) = parse_spec::<ConfigScanSummarySpec>(obj) {
            for (id, ctrl) in &spec.controls {
                if !ctrl.name.is_empty() {
                    name_lookup.entry(id.clone()).or_insert_with(|| ctrl.name.clone());
                }
            }
        }
    }

    let mut by_control: BTreeMap<String, ComplianceControl> = BTreeMap::new();
    for obj in &summary_items {
        let spec = match parse_spec::<ConfigScanSummarySpec>(obj) {
            Some(s) => s,
            None => continue,
        };
        for (id, ctrl) in &spec.controls {
            let entry = by_control.entry(id.clone()).or_insert_with(|| ComplianceControl {
                control_id: ctrl.control_id.clone(),
                name: name_lookup.get(id).cloned().unwrap_or_default(),
                severity: ctrl.severity.severity.clone(),
                score_factor: ctrl.severity.score_factor,
                total: 0,
                passed: 0,
                failed: 0,
                skipped: 0,
            });
            entry.total += 1;
            match ctrl.status.status.as_str() {
                "passed" => entry.passed += 1,
                "failed" => entry.failed += 1,
                "skipped" => entry.skipped += 1,
                _ => {}
            }
        }
    }

    let mut out: Vec<ComplianceControl> = by_control.into_values().collect();
    out.sort_by(|a, b| {
        b.score_factor.partial_cmp(&a.score_factor).unwrap_or(std::cmp::Ordering::Equal)
            .then(b.failed.cmp(&a.failed))
            .then(a.control_id.cmp(&b.control_id))
    });
    Ok(out)
}

// ── Network Neighborhoods ──

pub async fn network_namespace_list(
    client: &Client,
) -> Result<Vec<(String, usize)>, AppError> {
    let api = Api::all_with(client.clone(), &resources::network_neighborhood());
    let list = list_retry(&api, &ListParams::default()).await?;
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for obj in &list.items {
        let ns = obj.metadata.namespace.clone().unwrap_or_default();
        *m.entry(ns).or_default() += 1;
    }
    let mut out: Vec<(String, usize)> = m.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Ok(out)
}

pub async fn network_workload_list(
    client: &Client,
    namespace: &str,
) -> Result<Vec<NetworkNeighborhoodSummary>, AppError> {
    let api = Api::namespaced_with(client.clone(), namespace, &resources::network_neighborhood());
    let list = list_retry(&api, &ListParams::default()).await?;

    let mut out: Vec<NetworkNeighborhoodSummary> = list.items
        .into_iter()
        .filter_map(|obj| {
            let identity = extract_identity(&obj)?;
            let completion = annotation(&obj, "kubescape.io/completion");
            Some(NetworkNeighborhoodSummary { identity, completion })
        })
        .collect();
    out.sort_by(|a, b| a.identity.workload_name.cmp(&b.identity.workload_name));
    Ok(out)
}

pub async fn network_detail(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<(WorkloadIdentity, NetworkNeighborhoodSpec), AppError> {
    let api = Api::namespaced_with(client.clone(), namespace, &resources::network_neighborhood());
    let obj = get_retry(&api, name).await?;
    let identity = extract_identity(&obj)
        .ok_or_else(|| AppError::NotFound(format!("Missing identity for {name}")))?;
    let spec: NetworkNeighborhoodSpec = serde_json::from_value(obj.data.get("spec").cloned().unwrap_or_default())?;
    Ok((identity, spec))
}

// ── Generated Network Policies ──

pub async fn generated_policies_list(client: &Client) -> Result<Vec<GeneratedPolicySummary>, AppError> {
    let api = Api::all_with(client.clone(), &resources::generated_network_policy());
    let items = list_full(&api).await?;

    let mut out: Vec<GeneratedPolicySummary> = items
        .into_iter()
        .filter_map(|obj| {
            let name = obj.metadata.name.clone()?;
            let namespace = obj.metadata.namespace.clone().unwrap_or_default();
            let kind = label(&obj, "kubescape.io/workload-kind");
            let workload = label(&obj, "kubescape.io/workload-name");
            let inner: serde_json::Value = obj.data.get("spec")
                .and_then(|s| s.get("spec"))
                .cloned()
                .unwrap_or_default();
            let ingress_count = inner.get("ingress")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let egress_count = inner.get("egress")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            Some(GeneratedPolicySummary {
                name, namespace, kind, workload,
                ingress_count, egress_count,
            })
        })
        .collect();
    out.sort_by(|a, b| a.namespace.cmp(&b.namespace).then(a.workload.cmp(&b.workload)));
    Ok(out)
}

pub async fn generated_policy_detail(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<GeneratedPolicyDetail, AppError> {
    let api = Api::namespaced_with(client.clone(), namespace, &resources::generated_network_policy());
    let obj = get_retry(&api, name).await?;
    let workload = label(&obj, "kubescape.io/workload-name");
    let kind = label(&obj, "kubescape.io/workload-kind");
    let spec_val = obj.data.get("spec").and_then(|s| s.get("spec")).cloned().unwrap_or_default();
    let policy_yaml = serde_saphyr::to_string(&spec_val).unwrap_or_default();
    Ok(GeneratedPolicyDetail {
        namespace: namespace.to_string(),
        workload, kind, policy_yaml,
    })
}

// ── Known Servers ──

pub async fn known_servers_list(client: &Client) -> Result<Vec<KnownServerEntry>, AppError> {
    let api = Api::all_with(client.clone(), &resources::known_server());
    let items = list_full(&api).await?;

    let mut out: Vec<KnownServerEntry> = items
        .into_iter()
        .filter_map(|obj| {
            let name = obj.metadata.name.clone()?;
            let spec = obj.data.get("spec")?;
            Some(KnownServerEntry {
                name,
                server: spec.get("server").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                ip_block: spec.get("ipBlock").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

// ── Application Profiles (Runtime) ──

pub async fn runtime_namespace_list(
    client: &Client,
) -> Result<Vec<(String, usize)>, AppError> {
    let api = Api::all_with(client.clone(), &resources::application_profile());
    let list = list_retry(&api, &ListParams::default()).await?;
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for obj in &list.items {
        let ns = obj.metadata.namespace.clone().unwrap_or_default();
        *m.entry(ns).or_default() += 1;
    }
    let mut out: Vec<(String, usize)> = m.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Ok(out)
}

pub async fn runtime_workload_list(
    client: &Client,
    namespace: &str,
) -> Result<Vec<AppProfileSummary>, AppError> {
    let api = Api::namespaced_with(client.clone(), namespace, &resources::application_profile());
    let list = list_retry(&api, &ListParams::default()).await?;

    let mut out: Vec<AppProfileSummary> = list.items
        .into_iter()
        .filter_map(|obj| {
            let identity = extract_identity(&obj)?;
            let completion = annotation(&obj, "kubescape.io/completion");
            Some(AppProfileSummary { identity, completion })
        })
        .collect();
    out.sort_by(|a, b| a.identity.workload_name.cmp(&b.identity.workload_name));
    Ok(out)
}

pub async fn runtime_detail(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<(WorkloadIdentity, AppProfileSpec), AppError> {
    let api = Api::namespaced_with(client.clone(), namespace, &resources::application_profile());
    let obj = get_retry(&api, name).await?;
    let identity = extract_identity(&obj)
        .ok_or_else(|| AppError::NotFound(format!("Missing identity for {name}")))?;
    let spec: AppProfileSpec = serde_json::from_value(obj.data.get("spec").cloned().unwrap_or_default())?;
    Ok((identity, spec))
}

/// Get node-agent pod logs for runtime alerts.
pub async fn runtime_alerts(client: &Client) -> Result<Vec<RuntimeAlert>, AppError> {
    let pods_api: Api<k8s_openapi::api::core::v1::Pod> =
        Api::namespaced(client.clone(), "kubescape");
    let lp = ListParams::default().labels("app=node-agent");
    let pods = pods_api.list(&lp).await?;

    let mut alerts = Vec::new();
    for pod in &pods.items {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let log_params = kube::api::LogParams {
            tail_lines: Some(200),
            ..Default::default()
        };
        let logs = match pods_api.logs(&pod_name, &log_params).await {
            Ok(l) => l,
            Err(_) => continue,
        };
        for line in logs.lines() {
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
                let msg = entry.get("msg").and_then(|v| v.as_str()).unwrap_or_default();
                // Only include lines that look like alerts/detections
                if msg.contains("alert") || msg.contains("Alert") || msg.contains("detection")
                    || msg.contains("malicious") || msg.contains("unexpected")
                    || entry.get("RuleName").is_some()
                    || entry.get("ruleName").is_some()
                {
                    alerts.push(RuntimeAlert {
                        timestamp: entry.get("ts").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        message: msg.to_string(),
                        pod_name: entry.get("podName")
                            .or_else(|| entry.get("pod"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        namespace: entry.get("namespace")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        rule_name: entry.get("RuleName")
                            .or_else(|| entry.get("ruleName"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        node: pod_name.clone(),
                    });
                }
            }
        }
    }
    alerts.sort_by(|a, b| b.timestamp.partial_cmp(&a.timestamp).unwrap_or(std::cmp::Ordering::Equal));
    Ok(alerts)
}

// ── SBOM ──

pub async fn sbom_list(client: &Client) -> Result<Vec<SbomSummary>, AppError> {
    let api = Api::namespaced_with(client.clone(), "kubescape", &resources::sbom_syft());
    let list = list_retry(&api, &ListParams::default()).await?;

    let mut out: Vec<SbomSummary> = list.items
        .into_iter()
        .filter_map(|obj| {
            let name = obj.metadata.name.clone()?;
            Some(SbomSummary {
                name,
                image_tag: annotation(&obj, "kubescape.io/image-tag"),
                image_id: annotation(&obj, "kubescape.io/image-id"),
            })
        })
        .collect();
    out.sort_by(|a, b| a.image_tag.cmp(&b.image_tag));
    Ok(out)
}

pub async fn sbom_detail(client: &Client, name: &str) -> Result<(SbomSummary, SbomSpec), AppError> {
    let api = Api::namespaced_with(client.clone(), "kubescape", &resources::sbom_syft());
    let obj = get_retry(&api, name).await?;
    let summary = SbomSummary {
        name: obj.metadata.name.clone().unwrap_or_default(),
        image_tag: annotation(&obj, "kubescape.io/image-tag"),
        image_id: annotation(&obj, "kubescape.io/image-id"),
    };
    let spec: SbomSpec = serde_json::from_value(obj.data.get("spec").cloned().unwrap_or_default())?;
    Ok((summary, spec))
}

pub async fn sbom_filtered_detail(client: &Client, name: &str) -> Result<Option<SbomSpec>, AppError> {
    let api = Api::namespaced_with(client.clone(), "kubescape", &resources::sbom_syft_filtered());
    match get_retry(&api, name).await {
        Ok(obj) => Ok(Some(serde_json::from_value(obj.data.get("spec").cloned().unwrap_or_default())?)),
        Err(kube::Error::Api(resp)) if resp.code == 404 => Ok(None),
        Err(e) => Err(e.into()),
    }
}
