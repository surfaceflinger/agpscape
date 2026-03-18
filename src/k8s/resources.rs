use kube::api::ApiResource;

const GROUP: &str = "spdx.softwarecomposition.kubescape.io";
const VERSION: &str = "v1beta1";

fn ar(kind: &str, plural: &str) -> ApiResource {
    ApiResource {
        group: GROUP.into(),
        version: VERSION.into(),
        api_version: format!("{GROUP}/{VERSION}"),
        kind: kind.into(),
        plural: plural.into(),
    }
}

pub fn vulnerability_manifest_summary() -> ApiResource {
    ar("VulnerabilityManifestSummary", "vulnerabilitymanifestsummaries")
}

pub fn vulnerability_summary() -> ApiResource {
    ApiResource {
        group: GROUP.into(),
        version: VERSION.into(),
        api_version: format!("{GROUP}/{VERSION}"),
        kind: "VulnerabilitySummary".into(),
        plural: "vulnerabilitysummaries".into(),
    }
}

pub fn vulnerability_manifest() -> ApiResource {
    ar("VulnerabilityManifest", "vulnerabilitymanifests")
}

pub fn workload_configuration_scan_summary() -> ApiResource {
    ar("WorkloadConfigurationScanSummary", "workloadconfigurationscansummaries")
}

pub fn workload_configuration_scan() -> ApiResource {
    ar("WorkloadConfigurationScan", "workloadconfigurationscans")
}

pub fn network_neighborhood() -> ApiResource {
    ar("NetworkNeighborhood", "networkneighborhoods")
}

pub fn generated_network_policy() -> ApiResource {
    ar("GeneratedNetworkPolicy", "generatednetworkpolicies")
}

pub fn known_server() -> ApiResource {
    ar("KnownServer", "knownservers")
}

pub fn application_profile() -> ApiResource {
    ar("ApplicationProfile", "applicationprofiles")
}

pub fn sbom_syft() -> ApiResource {
    ar("SBOMSyft", "sbomsyfts")
}

pub fn sbom_syft_filtered() -> ApiResource {
    ar("SBOMSyftFiltered", "sbomsyftfiltereds")
}
