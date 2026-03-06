# conntrack-ebpf-exporter

## Overview
eBPF-based per-pod conntrack metrics exporter for Kubernetes. Attaches kprobes to the kernel conntrack subsystem and optionally reads Cilium CT maps to expose per-pod connection tracking metrics via Prometheus.

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square) [![made with Go](https://img.shields.io/badge/made%20with-Go-brightgreen)](http://golang.org) [![Github master branch build](https://img.shields.io/github/actions/workflow/status/zufardhiyaulhaq/conntrack-ebpf-exporter/master.yml?branch=master)](https://github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/actions/workflows/master.yml) [![GitHub issues](https://img.shields.io/github/issues/zufardhiyaulhaq/conntrack-ebpf-exporter)](https://github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/issues) [![GitHub pull requests](https://img.shields.io/github/issues-pr/zufardhiyaulhaq/conntrack-ebpf-exporter)](https://github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pulls)

## Installing

To install the chart with the release name `my-release`:

```console
helm repo add conntrack-ebpf-exporter https://zufardhiyaulhaq.com/conntrack-ebpf-exporter/charts/releases/
helm install my-conntrack-ebpf-exporter conntrack-ebpf-exporter/conntrack-ebpf-exporter --values values.yaml
```

## Prerequisite
- Kubernetes cluster with kernel >= 5.8 (CONFIG_DEBUG_INFO_BTF enabled)
- Nodes must have `bpftool` and `clang` available (included in the container image)
- Privileged container access (required for BPF program loading)
- Optional: Cilium CNI for Cilium CT map metrics
- Optional: Prometheus Operator for PodMonitor support

## Usage
1. Install with default values (deploys as DaemonSet to all nodes):
```console
helm install conntrack-ebpf-exporter conntrack-ebpf-exporter/conntrack-ebpf-exporter \
  --namespace kube-system
```

2. Enable PodMonitor for Prometheus Operator:
```console
helm install conntrack-ebpf-exporter conntrack-ebpf-exporter/conntrack-ebpf-exporter \
  --namespace kube-system \
  --set podMonitor.enabled=true
```

3. Enable metric breakdown (protocol and direction labels):
```console
helm install conntrack-ebpf-exporter conntrack-ebpf-exporter/conntrack-ebpf-exporter \
  --namespace kube-system \
  --set config.metricBreakdown="true"
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules |
| config.logLevel | string | `"info"` | Log level (debug, info, warn, error) |
| config.metricBreakdown | string | `"false"` | Enable protocol and direction breakdown labels |
| config.metricCacheInterval | string | `"30s"` | Cache interval for Cilium CT reads |
| config.metricsPort | string | `"9990"` | Metrics HTTP port |
| fullnameOverride | string | `""` | Override the full release name |
| image.pullPolicy | string | `"Always"` | Image pull policy |
| image.repository | string | `"ghcr.io/zufardhiyaulhaq/conntrack-ebpf-exporter"` | Container image repository |
| image.tag | string | `"v0.1.0"` | Overrides the image tag (default is the chart appVersion) |
| imagePullSecrets | list | `[]` | Image pull secrets for private registries |
| nameOverride | string | `""` | Override the chart name |
| nodeSelector | object | `{}` | Node selector for scheduling |
| podAnnotations | object | `{"sidecar.istio.io/inject":"false"}` | Pod annotations |
| podLabels | object | `{}` | Pod labels |
| podMonitor.enabled | bool | `false` | Create a PodMonitor for Prometheus Operator |
| podMonitor.honorLabels | bool | `true` | Honor labels from the exporter |
| podMonitor.interval | string | `""` | Scrape interval |
| podMonitor.labels | object | `{}` | Additional labels for the PodMonitor |
| podMonitor.path | string | `"/metrics"` | Scrape path |
| podSecurityContext | object | `{}` | Pod security context |
| replicaCount | int | `1` | Number of replicas (only applies if kind is Deployment, ignored for DaemonSet) |
| resources.limits.cpu | string | `"256m"` |  |
| resources.limits.memory | string | `"128Mi"` |  |
| resources.requests.cpu | string | `"50m"` |  |
| resources.requests.memory | string | `"64Mi"` |  |
| securityContext.privileged | bool | `true` | Run container as privileged (required for BPF) |
| serviceAccount.annotations | object | `{}` | Annotations to add to the ServiceAccount |
| serviceAccount.create | bool | `true` | Create a ServiceAccount |
| serviceAccount.name | string | `""` | The name of the ServiceAccount (generated if not set) |
| tolerations | list | `[{"operator":"Exists"}]` | Tolerations for scheduling |
| updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | Update strategy for the DaemonSet |

see example values file [here](https://github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/blob/main/charts/conntrack-ebpf-exporter/values.yaml)

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
