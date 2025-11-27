# Shai-Hulud Detection Scanner

A cross-platform security scanner for detecting the **Shai-Hulud** npm supply chain malware. Available for both Windows (PowerShell) and Unix/Linux/macOS (Bash).

## Background

Shai-Hulud is a sophisticated supply chain attack targeting npm packages that was first discovered in September 2025, with a more advanced variant (Shai-Hulud 2.0) appearing in November 2025. The malware compromises npm packages to:

- Harvest credentials and environment variables
- Exfiltrate secrets via webhook endpoints
- Install malicious GitHub Actions self-hosted runners
- Clone and manipulate private repositories

This scanner detects indicators of compromise (IOCs) from both variants.

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

## Requirements

### PowerShell (Windows)
- Windows PowerShell 5.1 or later
- Git (optional, for branch/remote analysis)
- npm (optional, for cache path detection)

### Bash (Linux/macOS/WSL)
- Bash 4.0 or later (for associative arrays)
- curl (for fetching IOC feeds)
- Git (optional, for branch/remote analysis)
- npm (optional, for cache path detection)
- Python 3 (for JSON parsing in postinstall hook analysis)
- Standard Unix utilities: `find`, `sha256sum`, `sha1sum`, `grep`

### S3 Scanning (Linux)
- Requires `mc` and `jq` to be installed
- Downloads all S3 assets to a folder in `/tmp`
- Then calls `Check-ShaiHulud-Dynamic.sh` the scan the download location
- Example `./s3-bucket-scanner.sh -a MY_KEY -s MY_SECRET -h MY.MINIO.INSTANCE -b BUCKET --path MY/PATH`
- Run `./s3-bucket-scanner.sh -h` for usage
- Requires `Check-ShaiHulud-Dynamic.sh` to be present in the same folder

## Installation

Clone or download the repository to your system:

```bash
git clone https://github.com/your-repo/shai-hulud-scanner.git
cd shai-hulud-scanner
```

Or download the individual script for your platform:
- **Windows**: `Check-ShaiHulud-Dynamic.ps1`
- **Unix/Linux/macOS**: `Check-ShaiHulud-Dynamic.sh`

## Usage

### PowerShell (Windows)

```powershell
# Allow script execution (session-only)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Quick scan (default) - fast, covers common IOCs
.\Check-ShaiHulud-Dynamic.ps1 -RootPaths "C:\Projects"

# Full scan - comprehensive, takes longer
.\Check-ShaiHulud-Dynamic.ps1 -RootPaths "C:\Projects" -ScanMode Full

# Scan multiple directories
.\Check-ShaiHulud-Dynamic.ps1 -RootPaths "C:\Projects", "D:\Work" -ScanMode Full

# Custom report output path
.\Check-ShaiHulud-Dynamic.ps1 -RootPaths "C:\Projects" -ReportPath "C:\Reports\scan.txt"
```

#### PowerShell Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-RootPaths` | `$env:USERPROFILE` | One or more directories to scan |
| `-ScanMode` | `Quick` | `Quick` for fast scan, `Full` for comprehensive |
| `-ReportPath` | `.\ShaiHulud-Scan-Report.txt` | Output file for detailed report |

### Bash (Linux/macOS/WSL)

```bash
# Make the script executable
chmod +x Check-ShaiHulud-Dynamic.sh

# Quick scan (default) - fast, covers common IOCs
./Check-ShaiHulud-Dynamic.sh -r ~/projects

# Full scan - comprehensive, takes longer
./Check-ShaiHulud-Dynamic.sh -r ~/projects -m full

# Scan multiple directories (comma-separated)
./Check-ShaiHulud-Dynamic.sh -r ~/projects,~/work -m full

# Custom report output path
./Check-ShaiHulud-Dynamic.sh -r ~/projects -o ~/reports/scan.txt

# Show help
./Check-ShaiHulud-Dynamic.sh -h
```

#### Bash Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-r, --roots` | `$HOME` | Comma-separated directories to scan |
| `-m, --mode` | `quick` | `quick` for fast scan, `full` for comprehensive |
| `-o, --report` | `./ShaiHulud-Scan-Report.txt` | Output file for detailed report |
| `-h, --help` | - | Show usage help |

## Scan Modes

**Quick Mode** (~10-30 seconds)
- Scans top-level `node_modules` only (depth-limited)
- Checks root `package.json` for suspicious hooks
- Hash-scans only files with suspicious names
- Skips npm cache, self-hosted runners, env patterns

**Full Mode** (~5-30+ minutes depending on codebase size)
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

## Performance Optimizations

The scanner is optimized for large codebases:

- **HashSet/associative array lookups** for O(1) package matching (vs O(n) iteration)
- **Scoped package separation** - pre-sorts `@scope/package` format for efficient matching
- **Depth-limited Quick mode** - avoids deep recursion in `node_modules`
- **Progress throttling** - updates every 50-100 items to reduce overhead (PowerShell)
- **Early termination** - skips redundant checks when matches found
- **Compiled regex** - single-pass pattern matching for npm cache scan

## Offline Support

Both scripts support offline operation:

1. On first successful run, the compromised packages list is cached locally to `compromised-packages-cache.txt`
2. If the IOC feed is unreachable, the scanner falls back to the cached snapshot
3. File-based IOC checks (hashes, filenames, patterns) work without network access

## Platform Differences

| Feature | PowerShell | Bash |
|---------|------------|------|
| Progress indicators | Yes (`Write-Progress`) | No |
| JSON parsing | Built-in (`ConvertFrom-Json`) | Requires Python 3 |
| Color output | Yes | Yes (ANSI codes) |
| ASCII banner | Yes | Yes |
| Parallel execution | No | No |

## Limitations

- **Read-only** - does not delete or modify any files
- **Network recommended** - fetches live IOC feeds (will continue with local checks if offline)
- **False positives possible** - some patterns (like `node -e` in postinstall) may flag legitimate packages
- **Bash requires Python 3** - for JSON parsing in postinstall hook analysis

## References

- [Wiz: Shai-Hulud npm Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [Wiz: Shai-Hulud 2.0 Ongoing Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Unit 42: npm Supply Chain Attack Analysis](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Sngular: Shai-Hulud Integrity Scanner](https://github.com/sngular/shai-hulud-integrity-scanner)

## Contributing

To add new IOCs, update the following sections in the scripts:

### PowerShell (`Check-ShaiHulud-Dynamic.ps1`)
- `$MaliciousFileNames` - known malicious filenames
- `$SuspiciousBranchPatterns` - git branch patterns
- `$MaliciousHashes` / `$MaliciousHashesSHA1` - file hashes
- `$SuspiciousWorkflowPatterns` - GitHub Actions patterns
- `$SuspiciousPostinstallPatterns` - npm script patterns

### Bash (`Check-ShaiHulud-Dynamic.sh`)
- `MALICIOUS_FILES` - known malicious filenames
- `SUSPICIOUS_BRANCH_PATTERNS` - git branch patterns
- `MAL_SHA256` / `MAL_SHA1` - file hashes
- `SUSPICIOUS_WORKFLOW_PATTERNS` - GitHub Actions patterns
- `SUSPICIOUS_HOOK_PATTERNS` - npm script patterns

## License

MIT
