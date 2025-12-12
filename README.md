# Shai-Hulud Detection Scanner

A cross-platform **pure Go** security scanner for detecting the **Shai-Hulud** npm supply chain malware.


- Easy to distribute as a single binary
- Cross-platform (Windows, macOS, and GNU/Linux)

---

## Background

Shai-Hulud is a sophisticated supply chain attack targeting npm packages that was first discovered in September 2025, with a more advanced variant (Shai-Hulud 2.0) appearing in November 2025. The malware compromises npm packages to:

- Harvest credentials and environment variables
- Exfiltrate secrets via webhook endpoints
- Install malicious GitHub Actions self-hosted runners
- Clone and manipulate private repositories

This scanner detects indicators of compromise (IOCs) from both variants.

---

## Features

The scanner performs the following checks:

| Check | Quick Mode | Full Mode | Description |
|-------|------------|-----------|-------------|
| Compromised npm packages | Yes | Yes | Fetches live IOC feeds and scans `node_modules` |
| npm cache scan | No | Yes | Scans npm cache for compromised packages |
| Malicious file artefacts | Yes | Yes | Detects known Shai-Hulud files (`shai-hulud.js`, `setup_bun.js`, etc.) |
| Git branch/remote analysis | Yes | Yes | Checks for suspicious branches and remotes |
| GitHub Actions workflows | Yes | Yes | Scans for malicious workflow patterns |
| Cloud credential exposure | Partial | Yes | Detects AWS/Azure/npm credential files |
| Self-hosted runner detection | No | Yes | Finds GitHub Actions runner installations |
| Postinstall hook analysis | Root only | Yes | Scans `package.json` for suspicious scripts |
| Hash-based detection | Targeted | Yes | SHA256/SHA1 matching against known malware |
| Migration suffix detection | No | Yes | Identifies `-migration` repo attack pattern |
| TruffleHog detection | PATH only | Yes | Detects credential harvesting tool |
| Env+exfil pattern scan | No | Yes | Finds code combining env access with exfiltration |

---

## Installation

### From Release Binaries

1. Download the latest release version appropriae to your platform(s)
1. Ensure this final in available on your `PATH`, or correctly installed via your Package Manager
1. Run the scanner with appropriate switches (see [CLI Usage](#cli-usage) below)

### From Source (Go 1.25+) for Development

To compile the souce, you will need to install the Go toolchain as this project is implemented in **pure Go**.

- **Minimum Go version**: `1.25`
- No CGO dependencies (cross-compilation friendly)

Please follow the [instructions appropriate to your platform](https://go.dev/doc/install).

Clone the repository and build the CLI:

```bash
git clone https://github.com/your-repo/go-Shai-Hulud-Scanner.git
cd go-Shai-Hulud-Scanner

# Run tests
go test ./...

# Build a local debug binary
go build -o shai-hulud-scanner ./cmd/scanner
```

With Go 1.25+ in your `PATH`, you can also use:

```bash
go install ./cmd/scanner
```

This will place `shai-hulud-scanner` into your `GOBIN` (or `$GOPATH/bin`).

### Using the Makefile

Once you have Go installed, you can use the provided `Makefile` shortcuts:

```bash
# Run tests
make test

# Build a local debug binary (bin/shai-hulud-scanner)
make debug

# Build common release binaries into dist/
make release-build
```
---

## CLI Usage

After building or installing the binary, you can run:

```bash
shai-hulud-scanner [options] [paths...]
```

**Note:** Go is sensitive to order and all `options` _must_ come first.

If no paths are provided, the scanner defaults to your home directory.

### CLI options

The available flags map directly to `cmd/scanner/main.go`:

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | `quick` | Scan mode: `quick` or `full` |
| `-report` | `./ShaiHulud-Scan-Report.txt` | File path for the detailed report |
| `-cache` | system temp dir | Path for compromised package cache file |
| `-no-banner` | `false` | Do not print the ASCII banner |
| `-files-only` | `false` | Only scan for malicious files (skip git, npm cache, etc.) |
| `-strict` | `false` | Exit 1 on ANY finding including warnings (old behavior) |
| `-warn-only` | `false` | Exit 0 on warnings, only fail on high+ severity findings |
| `-config` | - | Path to allowlist configuration file (JSON) |
| `-help` | - | Show help/usage information |
| `-V` | - | Print version and exit |

### Examples

```bash
# Quick scan of your home directory (default)
shai-hulud-scanner

# Full scan of your home directory
shai-hulud-scanner -mode full

# Quick scan of a specific project
shai-hulud-scanner /path/to/project

# Full scan of multiple projects with a custom report path
shai-hulud-scanner -mode full -report ./ShaiHulud-Scan-Report.txt /projects/app1 /projects/app2

# Files-only scan (skip git/npm cache/credentials) for CI
shai-hulud-scanner -files-only /workspace

# Strict mode: fail on ANY finding (old behavior)
shai-hulud-scanner -strict /path/to/project

# Warn-only mode: only fail on critical findings
shai-hulud-scanner -warn-only /path/to/project

# Use an allowlist configuration file
shai-hulud-scanner -config shai-hulud.config.json /path/to/project
```

---

## Scan Modes

**Quick Mode**
- Scans top-level `node_modules` only (depth-limited)
- Checks root `package.json` for suspicious hooks
- Hash-scans only files with suspicious names
- Skips npm cache, self-hosted runners, env patterns

**Full Mode**
- Recursive scan of all `node_modules` directories
- Complete npm cache analysis
- Full hash scan of all JS/TS files
- Deep postinstall hook analysis
- Self-hosted runner detection
- Environment variable exfiltration pattern detection

---

## Severity Levels & Exit Codes

Findings are classified into three severity levels:

| Severity | Exit Code | Description |
|----------|-----------|-------------|
| **Critical** | 2 | Confirmed malware (hash matches, malicious runners) |
| **High** | 1 | Known compromised packages, specific IOC files/patterns |
| **Warning** | 0 | Needs review, may be false positive |

### Finding Classification

| Finding Type | Severity | Rationale |
|--------------|----------|-----------|
| `malware-hash` | Critical | Confirmed malware signature |
| `malicious-runner` | Critical | Confirmed malicious runner |
| `node_modules` | High | Known compromised package |
| `npm-cache` | High | Known compromised package |
| `file-artefact` | High | Known malicious filename |
| `git-branch` | High | Specific Shai-Hulud IOC |
| `git-remote` | High | Specific Shai-Hulud IOC |
| `workflow-pattern` | High | Specific attack pattern |
| `workflow-content` | Warning | May be legitimate self-hosted |
| `credential-file` | Warning | Normal to have these files |
| `runner-installation` | Warning | May be legitimate |
| `postinstall-hook` | Warning | High false positive rate |
| `migration-attack` | Warning | May be legitimate naming |
| `trufflehog-*` | Warning | Legitimate security tool |
| `env-exfil-pattern` | Warning | Very high false positive rate |

### Exit Code Behavior

| Findings Present | Default | `-strict` | `-warn-only` |
|------------------|---------|-----------|--------------|
| Critical | Exit 2 | Exit 2 | Exit 2 |
| High | Exit 1 | Exit 1 | Exit 0 |
| Warning only | Exit 0 | Exit 1 | Exit 0 |
| None | Exit 0 | Exit 0 | Exit 0 |

**Default behavior**: Warnings alone will NOT fail your CI pipeline. Only high-confidence detections (compromised packages, known malware files) will cause exit code 1.

**Note**: The `-warn-only` flag controls exit codes based on finding severity, while `-files-only` controls what gets scanned (skipping git, npm cache, credentials). They serve different purposes and can be used together.

---

## Allowlist Configuration

You can create a JSON configuration file to exclude known-good packages, paths, or finding types.

### Configuration File Format

Create a file named `shai-hulud.config.json`:

```json
{
  "allowPackages": [
    "core-js",
    "@cypress/*",
    "@angular/*",
    "@babel/*"
  ],
  "allowPaths": [
    "**/node_modules/cypress/**",
    "**/node_modules/core-js/**",
    "**/test/**"
  ],
  "disableFindingTypes": [
    "credential-file",
    "env-exfil-pattern",
    "postinstall-hook"
  ]
}
```

### Configuration Options

| Option | Description |
|--------|-------------|
| `allowPackages` | Package names to exclude. Supports glob patterns like `@scope/*` |
| `allowPaths` | Path patterns to exclude. Supports `**` for recursive matching |
| `disableFindingTypes` | Finding types to completely disable |

**Security Warning**: Be cautious when using wildcard patterns (e.g., `@cypress/*`, `@angular/*`) in `allowPackages`. These patterns will allow **any** package in that namespace, including potentially malicious packages. Only use wildcards for well-known, trusted namespaces, and consider being more specific when possible (e.g., `@cypress/react` instead of `@cypress/*`).

### Usage

```bash
shai-hulud-scanner -config shai-hulud.config.json /path/to/project
```

### CI/CD Integration Examples

**GitHub Actions:**
```yaml
- name: Security Scan
  run: |
    shai-hulud-scanner -config .shai-hulud.config.json ./
```

**GitLab CI:**
```yaml
security_scan:
  script:
    - shai-hulud-scanner -config .shai-hulud.config.json ./
  allow_failure: false
```

**Azure DevOps:**
```yaml
- script: shai-hulud-scanner -config .shai-hulud.config.json ./
  displayName: 'Shai-Hulud Security Scan'
```

## Detected IOCs

### Malicious Files
- `shai-hulud.js`, `shai_hulud.js`
- `setup_bun.js`, `bun_environment.js`
- `discussion.yaml`
- `truffleSecrets.json`, `actionsSecrets.json`

### Workflow Patterns
- `formatter_*.yml` (Shai-Hulud 2.0 pattern)
- `self-hosted` runner configurations
- `SHA1HULUD` references
- `webhook.site` endpoints

### Git Indicators
- Branches containing `shai-hulud` or `SHA1HULUD`
- Remotes with `-migration` suffix
- Repositories named `*-migration`

### Known Malicious Hashes

**SHA256:**
- `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09` - bundle.js payload
- `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`
- `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`
- `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`

**SHA1 (Shai-Hulud 2.0):**
- `d1829b4708126dcc7bea7437c04d1f10eacd4a16` - setup_bun.js
- `d60ec97eea19fffb4809bc35b91033b52490ca11` - bun_environment.js
- `3d7570d14d34b0ba137d502f042b27b0f37a59fa` - bun_environment.js variant

## Output

The scanner produces:

1. **Console output** - Real-time progress and findings grouped by severity
2. **Report file** - Detailed findings written to the report path

### Example Output

**Clean scan (no findings):**
```
---- Scan Results ----
[*] Scan completed in 5s (QUICK mode)

[OK] No indicators of Shai-Hulud compromise were found in the scanned locations.
```

**Warnings only (exits 0 by default):**
```
---- Scan Results ----
[*] Scan completed in 5s (QUICK mode)

[!] WARNINGS: 3 (review recommended, may be false positives)
  [postinstall-hook] Suspicious postinstall: node -e
         /project/node_modules/core-js/package.json
  [credential-file] .env file
         /project/.env
  [env-exfil-pattern] Env access + exfil pattern
         /project/node_modules/cypress/runner.js

NOTE: Only warnings were found. Common packages like core-js, cypress, and
      angular may trigger these. Use -strict to fail on warnings.
```

**High-confidence detections (exits 1):**
```
---- Scan Results ----
[*] Scan completed in 5s (QUICK mode)

[!!] HIGH CONFIDENCE DETECTIONS: 2 (requires action)
  [node_modules] @example/malicious-pkg
         /project/node_modules/@example/malicious-pkg
  [file-artefact] shai-hulud.js
         /project/.github/workflows/shai-hulud.js

[!] WARNINGS: 1 (review recommended, may be false positives)
  [credential-file] .env file
         /project/.env
```

**Critical findings (exits 2):**
```
---- Scan Results ----
[*] Scan completed in 5s (FULL mode)

[!!!] CRITICAL FINDINGS: 1 (confirmed malware)
  [malware-hash] SHA256 match: Shai-Hulud bundle.js payload
         /project/dist/bundle.js

[!!] HIGH CONFIDENCE DETECTIONS: 1 (requires action)
  [node_modules] malicious-package
         /project/node_modules/malicious-package
```

## References

- [Wiz: Shai-Hulud npm Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [Wiz: Shai-Hulud 2.0 Ongoing Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Unit 42: npm Supply Chain Attack Analysis](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Sngular: Shai-Hulud Integrity Scanner](https://github.com/sngular/shai-hulud-integrity-scanner)

## License

[MIT](./LICENSE.txt)

