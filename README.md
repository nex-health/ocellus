# Ocellus

A TUI tool for monitoring TCP connections to Kubernetes pods via Cilium's BPF conntrack tables.

## Motivation

In Kubernetes clusters running Cilium, there is no easy way to answer the question: "who is connected to my pods right now?" Existing tools either show flow event streams (Hubble CLI), require a full observability stack (Pixie, Kubeshark), or only work one pod at a time (`kubectl exec` + `ss`).

Ocellus fills this gap by reading Cilium's kernel-level BPF conntrack tables directly from the Cilium agent, giving you a real-time, multi-pod dashboard of current connection state — all from the terminal, with no extra infrastructure and no tools required inside target pods.

Typical use cases:
- Monitoring connection distribution across database or service replicas
- Detecting connection leaks or imbalances between pod instances
- Quick operational checks ("how many clients are connected right now?") without leaving the terminal

## Installation

Download the latest binary for your platform from the [Releases](https://github.com/aurelcanciu/ocellus/releases) page:

```sh
# macOS (Apple Silicon)
curl -Lo ocellus https://github.com/aurelcanciu/ocellus/releases/latest/download/ocellus-darwin-arm64
chmod +x ocellus
sudo mv ocellus /usr/local/bin/

# macOS (Intel)
curl -Lo ocellus https://github.com/aurelcanciu/ocellus/releases/latest/download/ocellus-darwin-amd64
chmod +x ocellus
sudo mv ocellus /usr/local/bin/

# Linux (amd64)
curl -Lo ocellus https://github.com/aurelcanciu/ocellus/releases/latest/download/ocellus-linux-amd64
chmod +x ocellus
sudo mv ocellus /usr/local/bin/
```

Or install with Go 1.26+:

```sh
go install github.com/aurelcanciu/ocellus@latest
```

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
| `--state` | `all` | Connection state: `established`, `closing`, `all` |
| `--timeout` | `0` | Per-poll timeout in seconds (0 = no timeout) |
| `--kubeconfig` | standard | Path to kubeconfig |
| `-o, --output-format` | `jsonl` | Capture format: `jsonl`, `json`, `csv`, `text` |
| `-f, --output-file` | auto | Capture output file path |
| `--dump` | off | Non-interactive dump mode (bypasses TUI) |
| `--repeat` | `0` | Repeat interval in seconds for dump mode (0 = one-shot) |
| `--version` | | Print version and exit |

### Examples

```sh
# TUI mode
ocellus -n production -p 5432 deploy/pgbouncer
ocellus -p 5432-5440 --state all sts/postgres
ocellus --src 10.4.166.0/24 my-pod-name

# Dump mode (non-interactive)
ocellus --dump -n production -p 5432 deploy/pgbouncer          # one-shot dump to stdout
ocellus --dump -o json -f snapshot.json deploy/myapp            # JSON to file
ocellus --dump --repeat 60 -f connections.jsonl sts/postgres    # periodic dump every 60s
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
| `d` | Dump snapshot to file |
| `R` | Toggle continuous recording |
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
| `s` | Cycle sort (src, port, proto, state, bytes) |
| `S` | Toggle reverse sort |
| `/` | Search peers by IP |
| `n/N` | Next/prev search match |
| `Esc` | Back to pod list / clear search |
| `p`, `Space` | Toggle pause |
| `q`, `Ctrl+C` | Quit |

## Capturing and Recording

Ocellus can capture connection state to files for later analysis.

### On-demand snapshots

Press `d` in the TUI to dump the current connection state to a file. The file is created in the current directory with an auto-generated name (e.g. `ocellus-2026-02-25T14-30-00.jsonl`), or at the path specified by `--output-file`.

### Continuous recording

Press `R` in the TUI to toggle continuous recording. While active, every poll result is written to the capture file and a `[REC]` indicator appears in the header. Connection events (new peers, disconnects, pod lifecycle, traffic spikes) are also logged.

### Dump mode

Use `--dump` for non-interactive, scriptable captures that bypass the TUI entirely:

```sh
# One-shot snapshot to stdout
ocellus --dump -p 5432 deploy/pgbouncer

# Periodic snapshots every 30s to a file
ocellus --dump --repeat 30 -f connections.jsonl deploy/pgbouncer

# CSV format for spreadsheet import
ocellus --dump -o csv -f snapshot.csv sts/postgres
```

### Output formats

| Format | Description |
|--------|-------------|
| `jsonl` | One JSON object per line (default) — structured, streamable |
| `json` | Pretty-printed JSON — human-readable |
| `csv` | CSV with headers — spreadsheet/database import |
| `text` | Human-readable table — similar to TUI display |

### Event detection

When recording continuously (TUI `R` key), ocellus detects and logs events by comparing consecutive snapshots:

- **peer_added** / **peer_removed** — connection lifecycle
- **pod_discovered** / **pod_exited** — pod lifecycle
- **traffic_spike** — byte count exceeds 2x the previous poll
- **poll_error** — new polling errors

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
