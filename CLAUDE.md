# CLAUDE.md - Rusty Pcap

## Project Overview

Rusty Pcap is a Rust-based tool for searching and filtering PCAP (network packet capture) files. It supports filtering by IP addresses, ports, and timestamps, and can run as a CLI tool, REST API server, or Sguil PCAP agent.

**License:** GNU General Public License v3 (GPL-3.0)

## Repository Structure

```
rusty-pcap/                     # Workspace root
├── rusty-pcap/                 # Binary crate (entry point)
│   ├── src/main.rs             # CLI arg parsing, mode selection (CLI/server/agent)
│   ├── examples/               # Usage examples (hello.rs, server_example.rs)
│   └── Cargo.toml
├── rusty-pcap-lib/             # Library crate (core logic)
│   ├── src/
│   │   ├── lib.rs              # Config, PcapFilter, Cli structs; config file parsing
│   │   ├── api_server.rs       # Rocket REST API (GET /, /pcap, /status), CORS, TLS
│   │   ├── cli.rs              # CLI search execution and timestamp validation
│   │   ├── input_validation.rs # Port and timestamp validation helpers
│   │   ├── packet_parse.rs     # IPv4/IPv6 packet filtering (TCP, UDP, ICMP, VLAN)
│   │   ├── pcap_agent.rs       # Sguil agent: TLS connections, async command processing
│   │   ├── search_pcap.rs      # Directory traversal, PCAP file discovery, timestamp matching
│   │   └── write_pcap.rs       # Filtered PCAP output file generation
│   └── Cargo.toml
├── config.toml                 # Default application configuration
├── .github/workflows/          # CI/CD (build, test, clippy, release)
├── Cargo.toml                  # Workspace definition
└── README.md
```

## Build & Development Commands

This is a Rust workspace using Cargo. Edition 2021.

```bash
# Build the entire workspace
cargo build --verbose

# Run tests
cargo test --verbose

# Run clippy linter
cargo clippy --all-features

# Run the binary
cargo run -- [OPTIONS]

# Run with a config file
cargo run -- -c config.toml

# Run as API server
cargo run -- -c config.toml --server
```

### Build Notes

- OpenSSL is vendored via `openssl-sys` with the `vendored` feature — no system OpenSSL required.
- The library crate (`rusty-pcap-lib`) contains almost all logic; the binary crate is a thin entry point.
- `Cargo.lock` is gitignored.

## Configuration

The application uses TOML configuration via `config.toml`. Local overrides go in `config.local.toml` (gitignored).

Key settings:
- `log_level`: "debug", "info", "warn", "error"
- `pcap_directory`: Comma-separated list of directories to scan for PCAPs
- `output_directory`: Where filtered output PCAPs are written
- `enable_server`: Whether to start the REST API
- `search_buffer`: Time window around timestamp (e.g., "30s", "5m", "1h", "1d")
- `enable_cors`: CORS support for the API
- `[server]`: Address, port, optional TLS cert/key paths
- `[pcap_agent]`: Sguil agent settings (server, port, sensor name, intervals)

## Architecture & Key Concepts

### Three Operating Modes

1. **CLI mode** (default): Search PCAPs from command line with filters, output matching packets
2. **Server mode** (`--server`): Rocket v0.5 REST API accepting search queries via HTTP
3. **Agent mode** (`pcap_agent.enable = true`): Connects to Sguil server over TLS, responds to PCAP requests

### Core Data Flow

1. `PcapFilter` struct defines the search criteria (IPs, ports, timestamp, buffer)
2. `search_pcap` finds candidate PCAP files by scanning directories and matching timestamps in filenames (10-digit Unix timestamps)
3. `packet_parse` reads each PCAP and filters packets by IP/port at the Ethernet/IP/TCP/UDP/ICMP level
4. `write_pcap` writes matching packets to a new output PCAP file

### Key Types

- `Config` (`lib.rs`): Application-wide configuration deserialized from TOML
- `PcapFilter` (`lib.rs`): Search filter; implements Rocket's `FromForm` for query parameter binding
- `Cli` (`lib.rs`): CLI argument parser via `structopt`
- `RocketConfig` (`lib.rs`): Server bind address, port, TLS settings

### API Endpoints

| Route     | Method | Description                                    |
|-----------|--------|------------------------------------------------|
| `/`       | GET    | Welcome message                                |
| `/pcap`   | GET    | Search PCAPs and return filtered file download  |
| `/status` | GET    | Server uptime and request metrics              |

Query parameters for `/pcap`: `ip`, `src_ip`, `dest_ip`, `port`, `src_port`, `dest_port`, `timestamp`, `buffer`

### Packet Parsing

- Supports Ethernet, IPv4, IPv6, TCP, UDP, ICMP
- Handles nested VLAN-tagged packets
- IP filter matches bidirectionally by default (`ip` param) or directionally (`src_ip`/`dest_ip`)
- Port filter supports up to 2 ports, bidirectional or directional

## Testing

Tests are inline unit tests using `#[cfg(test)]` modules within source files.

```bash
# Run all tests
cargo test --verbose
```

Test coverage by module:
- `packet_parse.rs`: IPv4/IPv6 UDP and TCP packet filtering (5 tests)
- `write_pcap.rs`: Output file creation and error handling (3 tests)
- `search_pcap.rs`: Duration parsing, timestamp extraction, directory traversal (4 tests)
- `input_validation.rs`: Port and timestamp validation (4 tests)

There is no separate test directory — all tests live alongside the code they test.

## CI/CD

GitHub Actions workflows in `.github/workflows/`:

- **rust.yml**: Runs `cargo build` and `cargo test` on push/PR to `main`
- **rust-clippy.yml**: Runs clippy with SARIF output, uploads to GitHub Security tab. Triggers on push/PR to `main` and weekly schedule.
- **release.yml**: Multi-platform release builds on tag push. Targets:
  - `x86_64-unknown-linux-musl`
  - `x86_64-unknown-linux-gnu`
  - `aarch64-apple-darwin`

## Code Conventions

- **Rust edition**: 2021
- **Async runtime**: Tokio (full features)
- **Web framework**: Rocket v0.5 with JSON support
- **CLI parsing**: `structopt`
- **Serialization**: `serde` + `serde_json` for JSON, `toml` for config
- **Logging**: `log` facade with `env_logger` backend
- **Error handling**: `Box<dyn std::error::Error>` for config parsing; `Result` types throughout
- **Clippy**: `#![allow(clippy::blocks_in_conditions)]` is set in `lib.rs` (Rocket macro compatibility)
- **License headers**: GPL-3.0 header blocks at the top of source files

## Files to Never Commit

Per `.gitignore`:
- `/target` — build artifacts
- `Cargo.lock` — lock file (library-style policy)
- `config.local.toml` — local config overrides
- `certs/` — TLS certificates
- `output/*` — generated PCAP output files
- IDE files (`.idea/`, `.vscode/`, `.DS_Store`)
