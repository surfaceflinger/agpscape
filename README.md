# ˚ʚ agpscape ɞ˚

a cute little web UI for browsing [Kubescape](https://kubescape.io/) data in your Kubernetes cluster.

![agpscape preview](https://files.blahaj.pl/misc/gh-previews/kubescape.png)

point it at a cluster with Kubescape installed and it gives you a dashboard for everything Kubescape knows - vulnerabilities, compliance posture, misconfigurations, network neighborhoods, runtime profiles, SBOMs, and more.

## why

other solutions are either to install a bloated dashboard with kubescape as a plugin, or to use a proprietary k8s "IDE"

## features

- **vulnerabilities** - CVEs across all container images, filterable by fixability, sortable by CVSS
- **compliance** - NSA, MITRE, CIS framework controls at a glance
- **configuration** - security misconfigurations and CIS benchmark results per workload
- **network** - network neighborhoods, auto-generated network policies, known servers
- **runtime** - application profiles and runtime detection alerts
- **sbom** - software bill of materials with Kubescape's relevance filtering

## running it

you need a Kubernetes cluster with [Kubescape operator](https://kubescape.io/docs/operator/) installed

```sh
# with nix
nix run .

# or with cargo
cargo run
```

it picks a random port and opens your browser automatically. that's it.

## disclaimer

this project was written 100% by an LLM ^_^

if it works, that's cool. if it doesn't, well, idc.
