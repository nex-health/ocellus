# Ocellus

A TUI tool for monitoring TCP connections to Kubernetes pods via Cilium's BPF conntrack tables.

## Usage

```
ocellus [flags] <target>
```

### Target formats

```
deployment/name   deploy/name
statefulset/name  sts/name
daemonset/name    ds/name
replicaset/name   rs/name
pod-name
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-n, --namespace` | `default` | Kubernetes namespace |
| `-p, --port` | all | TCP port or range (e.g. `5432`, `5432-5440`) |
| `-i, --interval` | `10` | Polling interval in seconds |
| `--proto` | `tcp` | Protocol filter: `tcp`, `udp`, or `tcp,udp` |
| `--src` | all | Source IP or CIDR filter (e.g. `10.4.166.0/24`) |
| `--state` | `established` | Connection state: `established`, `closing`, `all` |
| `--timeout` | `0` | Per-poll timeout in seconds (0 = no timeout) |
| `--kubeconfig` | standard | Path to kubeconfig |

### Examples

```sh
ocellus -n production -p 5432 deploy/pgbouncer
ocellus -p 5432-5440 --state all sts/postgres
ocellus --src 10.4.166.0/24 my-pod-name
```

## Keybindings

### Pod list

| Key | Action |
|-----|--------|
| `j/k`, `Up/Down` | Navigate pods |
| `Enter` | View peer details |
| `Tab` / `Shift+Tab` | Jump to next/prev pod with connections |
| `gg` | Jump to top |
| `G` | Jump to bottom |
| `H/M/L` | Top/middle/bottom of screen |
| `Ctrl+d` / `Ctrl+u` | Half-page down/up |
| `p`, `Space` | Toggle pause |
| `r` | Force refresh |
| `?` | Help |
| `q`, `Ctrl+C` | Quit |

### Peer detail

| Key | Action |
|-----|--------|
| `j/k`, `Up/Down` | Scroll peers |
| `gg` | Jump to top |
| `G` | Jump to bottom |
| `H/M/L` | Top/middle/bottom of screen |
| `Ctrl+d` / `Ctrl+u` | Half-page down/up |
| `PgUp/PgDn` | Page scroll |
| `Home/End` | Jump to top/bottom |
| `s` | Cycle sort (src, port, proto, state) |
| `S` | Toggle reverse sort |
| `/` | Search peers by IP |
| `n/N` | Next/prev search match |
| `Esc` | Back to pod list / clear search |
| `p`, `Space` | Toggle pause |
| `q`, `Ctrl+C` | Quit |

## Prerequisites

- Kubernetes cluster with [Cilium](https://cilium.io/) CNI
- `kubectl` access with permissions to exec into Cilium agent pods in `kube-system`

## Building

```sh
make build          # dev build
make release        # optimized, stripped, version-stamped
make test           # run tests
make race           # run tests with race detector
make lint           # go vet
```
