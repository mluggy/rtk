# RTK Security Audit & Compilation Guide

## Overview

~78K lines of Rust across 60+ modules. A CLI proxy that intercepts commands, filters their output, and tracks usage. It also installs hooks into Claude Code that auto-approve rewritten commands.

---

## WHAT'S GOOD

### 1. Hook Integrity System (integrity.rs)
One of the most security-conscious features. SHA-256 verification of the `rtk-rewrite.sh` hook file at runtime. If the hook is tampered with, RTK refuses to execute and exits with code 1. Hash file is stored read-only (0o444). References an actual security advisory (SA-2025-RTK-001). This directly addresses the fact that the hook issues `permissionDecision: "allow"` -- so tampering with it would be a command injection vector.

### 2. Telemetry Opt-Out
Multiple opt-out mechanisms: `RTK_TELEMETRY_DISABLED=1` env var, `config.toml` setting (`telemetry.enabled = false`). Self-hosted builds have no telemetry at all (URL is `option_env!`, absent if not set at compile time).

### 3. Sensitive Environment Variable Masking (env_cmd.rs)
The `rtk env` command masks values for keys containing `key`, `secret`, `password`, `token`, `credential`, `auth`, `private`, `api_key`, `jwt` -- showing only first 2 and last 2 characters.

### 4. No `unwrap()` Policy
The codebase consistently uses `anyhow::Result` with `.context()`. Graceful degradation throughout: if a filter fails, fall back to raw command output.

### 5. Input Sanitization (tee.rs)
Filename slugs for tee output are sanitized -- only alphanumeric, underscore, and hyphen allowed; truncated to 40 chars. Prevents path traversal in tee filenames.

### 6. Good Dependency Choices
No async runtime (tokio), minimal attack surface. Dependencies are well-known, auditable Rust crates. `rusqlite` uses `bundled` feature (embeds SQLite, no system dependency).

### 7. Build Determinism
`build.rs` sorts filter files alphabetically for deterministic output. Validates combined TOML at build time. Detects duplicate filter names.

---

## WHAT'S BAD / SECURITY CONCERNS

### 1. Telemetry Sends Machine-Identifying Data (CRITICAL)

**File**: `src/telemetry.rs:49-84`

The telemetry ping sends:
- **Device hash**: SHA-256 of `hostname + username` -- this is a **stable device fingerprint**
- OS, arch, install method
- Number of commands run in 24h
- Top 5 commands used
- Overall savings percentage
- Total tokens saved (lifetime + 24h)

**The device hash is reversible for short hostnames/usernames** (brute-forceable). It's sent to whatever URL is compiled in via `RTK_TELEMETRY_URL`. The auth token (`RTK_TELEMETRY_TOKEN`) is also baked into official release binaries.

**Risk**: If the telemetry endpoint is compromised, an attacker gets a map of every RTK user's machine identifier, OS, architecture, and development activity patterns.

**Mitigation when self-compiling**: Don't set `RTK_TELEMETRY_URL` -- telemetry is completely dead without it.

### 2. The Hook Auto-Approves Commands (HIGH)

**File**: `hooks/rtk-rewrite.sh:52-61`

The hook outputs `"permissionDecision": "allow"` -- this **bypasses Claude Code's permission prompt** for any rewritten command. While the integrity check (SHA-256) is a good defense, the security model fundamentally trusts:
- The `rtk rewrite` binary to only produce safe rewrites
- The `jq` binary on the system
- The shell environment

If any of these are compromised (e.g., a malicious `jq` earlier in `$PATH`), arbitrary commands could be auto-approved silently.

### 3. Shell Injection via `runner.rs` (MEDIUM-HIGH)

**File**: `src/runner.rs:14-27`

```rust
Command::new("sh")
    .args(["-c", command])
```

The `run_err` and `run_test` functions pass user-provided strings directly to `sh -c`. The `command` parameter comes from CLI arguments. While this is by design (it's a command proxy), the string is passed through a shell interpreter, which means shell metacharacters are interpreted. This is the expected behavior but worth noting -- RTK inherits whatever the user passes.

### 4. `discover` Module Reads All Claude Code Sessions (MEDIUM)

**File**: `src/discover/provider.rs:119-234`

The `rtk discover` and `rtk learn` commands read JSONL session files from `~/.claude/projects/`. These contain:
- Every command Claude Code executed
- Command outputs (first 1000 chars)
- Error status

This data stays local, but the module has broad read access to Claude Code's session history. If RTK were compromised, this would be a rich data source.

### 5. No TLS Certificate Verification Configuration (LOW-MEDIUM)

**File**: `src/telemetry.rs:74-83`

The `ureq` HTTP client is used with default settings. While `ureq` does TLS verification by default, there's no certificate pinning. A MITM attacker with a trusted CA certificate could intercept telemetry data.

### 6. SQLite Database Has No Encryption (LOW)

**File**: `src/tracking.rs`

The tracking database at `~/.local/share/rtk/tracking.db` stores every command run through RTK, with timestamps. It's a plain SQLite file readable by any process running as the same user. This is a minor local information disclosure -- it reveals your development activity patterns.

### 7. Tee Output May Contain Secrets (LOW)

**File**: `src/tee.rs`

When commands fail, raw output is saved to `~/.local/share/rtk/tee/`. This output could contain secrets if the failing command printed them to stdout/stderr (e.g., a misconfigured `env` dump, a database connection string in an error message). Files are world-readable by default (no explicit chmod).

### 8. Release Binaries Have Embedded Telemetry Credentials

**File**: `.github/workflows/release.yml:76-77`

```yaml
RTK_TELEMETRY_URL: ${{ vars.RTK_TELEMETRY_URL }}
RTK_TELEMETRY_TOKEN: ${{ secrets.RTK_TELEMETRY_TOKEN }}
```

Official release binaries have the telemetry URL and auth token compiled in via `option_env!`. Anyone can extract these from the binary with `strings`. The token grants write access to the telemetry endpoint.

---

## WHAT'S MISSING

### 1. No `Cargo.lock` Committed
There's no `Cargo.lock` in the repo (or it's gitignored). For a binary application, the lock file should be committed to ensure reproducible builds and prevent supply chain attacks via dependency version drift.

### 2. No Dependency Audit CI Step
The release workflow doesn't run `cargo audit` or `cargo deny` to check for known vulnerabilities in dependencies.

### 3. No Sandboxing for Proxied Commands
RTK runs every proxied command with the same privileges as the user. There's no seccomp, sandbox, or capability restriction.

### 4. No Rate Limiting on Telemetry Endpoint
The 23-hour ping interval is enforced client-side only. A modified binary could flood the telemetry endpoint.

### 5. No Signature Verification for Updates
No mechanism to verify that a new RTK binary is authentic. The Homebrew formula uses SHA-256 checksums but these come from the same GitHub release -- a compromised release would include matching checksums.

### 6. File Permission Hardening for Tee and DB
Neither the tee files nor the SQLite database are created with restrictive permissions (e.g., 0o600). They inherit the default umask.

---

## DATA FLOW SUMMARY

| What | Where | Leaves Machine? |
|------|-------|-----------------|
| Command history + token savings | `~/.local/share/rtk/tracking.db` (SQLite) | No |
| Failed command raw output | `~/.local/share/rtk/tee/*.log` | No |
| Hook audit log | `~/.local/share/rtk/hook-audit.log` | No |
| Config | `~/.config/rtk/config.toml` | No |
| Telemetry marker | `~/.local/share/rtk/.telemetry_last_ping` | No |
| Hook warning marker | `~/.local/share/rtk/.hook_warn_last` | No |
| Claude Code session data | `~/.claude/projects/` (read-only) | No |
| **Telemetry ping** | **RTK_TELEMETRY_URL** (if compiled in) | **YES** -- device hash, OS, arch, usage stats |

---

## COMPILATION TUTORIAL

### Prerequisites

1. **Rust toolchain** (1.70+ recommended):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

2. **Git**:
```bash
# macOS
xcode-select --install

# Ubuntu/Debian
sudo apt install git build-essential

# Fedora
sudo dnf install git gcc
```

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/rtk-ai/rtk.git
cd rtk

# IMPORTANT: Verify what you're building
git log --oneline -5
cat Cargo.toml | head -10  # Confirm package name = "rtk"
```

### Debug Build (fast compilation, no optimization)

```bash
cargo build
# Binary at: target/debug/rtk
./target/debug/rtk --version
```

### Release Build (optimized, stripped)

```bash
cargo build --release
# Binary at: target/release/rtk
ls -lh target/release/rtk   # Should be <5MB
./target/release/rtk --version
```

**Key point**: Building yourself means `RTK_TELEMETRY_URL` and `RTK_TELEMETRY_TOKEN` are **not set** -- telemetry is completely inert. The `option_env!` macro returns `None`, and `maybe_ping()` returns immediately at line 14.

### Install to Your PATH

```bash
# Option A: cargo install (copies to ~/.cargo/bin/)
cargo install --path .

# Option B: manual copy
cp target/release/rtk /usr/local/bin/
# or
cp target/release/rtk ~/.local/bin/
```

### Verify Installation

```bash
rtk --version          # Should show "rtk 0.29.0"
rtk gain               # Should show token savings (or empty if first run)
rtk git status         # Should show compact git status
```

### Run Tests Before Trusting the Build

```bash
# All three quality gates
cargo fmt --all --check   # Code formatting
cargo clippy --all-targets  # Lint warnings
cargo test --all          # Unit tests (~105+ tests)
```

### Optional: Build DEB/RPM Packages

```bash
# DEB (Debian/Ubuntu)
cargo install cargo-deb
cargo deb
ls target/debian/*.deb

# RPM (Fedora/RHEL)
cargo install cargo-generate-rpm
cargo build --release
cargo generate-rpm
ls target/generate-rpm/*.rpm
```

### Cross-Compilation

```bash
# Add target
rustup target add aarch64-apple-darwin      # Apple Silicon
rustup target add x86_64-unknown-linux-musl  # Linux static

# Build for target
cargo build --release --target aarch64-apple-darwin
```

### Security-Hardened Build

If you want maximum control:

```bash
# 1. Audit dependencies first
cargo install cargo-audit
cargo audit

# 2. Build with no telemetry (default when self-compiling)
cargo build --release
# Verify: strings target/release/rtk | grep -i telemetry
# Should find no URLs

# 3. Verify no network calls in the binary
strings target/release/rtk | grep -E 'https?://'
# Should only show documentation URLs, not telemetry endpoints

# 4. Set restrictive permissions on data directories
mkdir -p ~/.local/share/rtk
chmod 700 ~/.local/share/rtk
```

### Initialize for Claude Code (Optional)

```bash
# Global hook setup (modifies ~/.claude/settings.json)
rtk init -g --auto-patch

# Verify hook integrity
rtk verify
# Should show: "PASS  hook integrity verified"

# Or project-local only (adds to ./CLAUDE.md)
rtk init
```

### Disable Telemetry Permanently (Even If Compiled In)

```bash
# Option 1: Environment variable
echo 'export RTK_TELEMETRY_DISABLED=1' >> ~/.zshrc

# Option 2: Config file
mkdir -p ~/.config/rtk
cat > ~/.config/rtk/config.toml << 'EOF'
[telemetry]
enabled = false
EOF
```
