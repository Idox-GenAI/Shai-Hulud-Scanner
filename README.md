# Shai-Hulud Detection Scanner

A cross-platform **pure Go** security scanner for detecting the **Shai-Hulud** npm supply chain malware.


- Easy to distribute as a single binary
- Cross-platform (Windows, macOS, Linux)

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

## Requirements

### Go toolchain

This project is implemented in **pure Go**.

- **Minimum Go version**: `1.25`
- No CGO dependencies (cross-compilation friendly)

### Supported platforms

The scanner is intended to run on:

- Windows (amd64, arm64)
- macOS (amd64, arm64/Apple Silicon)
- Linux (amd64, arm64)

All platform support is handled via standard Go cross-compilation.

---

## Installation

### From source (Go 1.25+)

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

## Usage (Go CLI)

After building or installing the binary, you can run:

```bash
shai-hulud-scanner [options] [paths...]
```

If no paths are provided, the scanner defaults to your home directory.

### CLI options

The available flags map directly to `cmd/scanner/main.go`:

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | `quick` | Scan mode: `quick` or `full` |
| `-report` | `./ShaiHulud-Scan-Report.txt` | File path for the detailed report |
| `-no-banner` | `false` | Do not print the ASCII banner |
| `-files-only` | `false` | Only scan for malicious files (skip git, npm cache, etc.) |
| `-help` | - | Show help/usage information |
| `-version` | - | Print version and exit |

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

1. **Console output** - Real-time progress and findings
2. **Report file** - Detailed findings written to the report path

### Example Output

```
[OK] No indicators of Shai-Hulud compromise were found in the scanned locations.
```

Or if issues are found:

```
[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND: 3 item(s)

Type              Package/Indicator                    Location
----              -----------------                    --------
node_modules      @example/malicious-pkg               C:\Projects\app\node_modules\...
workflow-content  Workflow contains: self-hosted       C:\Projects\app\.github\workflows\ci.yml
malware-hash      SHA256 match: Shai-Hulud bundle.js   C:\Projects\app\dist\bundle.js
```

## References

- [Wiz: Shai-Hulud npm Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [Wiz: Shai-Hulud 2.0 Ongoing Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Unit 42: npm Supply Chain Attack Analysis](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Sngular: Shai-Hulud Integrity Scanner](https://github.com/sngular/shai-hulud-integrity-scanner)

## License

[MIT](./LICENSE.txt)

