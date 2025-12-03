# Project Guidelines

## Project Overview

**Shai-Hulud Detection Scanner** is a cross-platform security scanner for detecting the Shai-Hulud npm supply chain malware. This project is being ported from shell scripts (PowerShell/Bash) to pure Go for improved cross-platform compatibility, maintainability, and distribution.

### Purpose
The scanner detects indicators of compromise (IOCs) from Shai-Hulud malware variants, including:
- Compromised npm packages
- Malicious file artifacts
- Suspicious Git branches and remotes
- Malicious GitHub Actions workflows
- Cloud credential exposure
- Self-hosted runner installations
- Postinstall hook analysis
- Hash-based malware detection

## Technology Stack

### Go Version
- **Go 1.25** (minimum required version)
- All code must be compatible with Go 1.25 features and syntax

### Target Platforms
This project must support cross-compilation for:
- **Windows** (amd64, arm64)
- **macOS** (amd64, arm64/Apple Silicon)
- **Linux** (amd64, arm64)

### Pure Go Implementation
- All functionality must be implemented in pure Go
- **No CGO dependencies** - to ensure easy cross-compilation
- **No shell script dependencies** at runtime
- Use Go standard library where possible

## Build & Release

### GoReleaser
This project uses [GoReleaser](https://goreleaser.com/) for building and packaging releases.

GoReleaser will be configured to:
- Build binaries for Windows, macOS, and Linux
- Create rpms and debs for Linux and archlinux packages while creating an exe for windows
- Generate checksums
- Support multiple architectures (amd64, arm64)

### Building Locally
```bash
# Standard build
go build -o shai-hulud-scanner ./...

# Run tests
go test ./...

# Build for specific platform
GOOS=windows GOARCH=amd64 go build -o shai-hulud-scanner.exe ./...
GOOS=darwin GOARCH=arm64 go build -o shai-hulud-scanner ./...
GOOS=linux GOARCH=amd64 go build -o shai-hulud-scanner ./...
```

## Testing

### Unit Tests
- All packages must have accompanying unit tests
- Test files should follow Go conventions: `*_test.go`
- Aim for meaningful test coverage, especially for:
  - IOC detection logic
  - File scanning functions
  - Hash computation and matching
  - Cross-platform path handling

### Running Tests
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./...

# Run specific package tests
go test -v ./pkg/scanner/...
```

### Test Requirements
- Tests should be runnable without external dependencies
- Use table-driven tests where appropriate
- Mock filesystem operations for consistent testing
- Tests must pass on all supported platforms

## Code Style

### General Guidelines
- Follow standard Go conventions and idioms
- Use `gofmt` for formatting
- Use `go vet` and `staticcheck` for linting
- Keep functions focused and testable
- Use meaningful variable and function names

### Project Structure (Recommended)
```
go-Shai-Hulud-Scanner/
├── cmd/
│   └── scanner/          # Main application entry point
├── pkg/
│   ├── scanner/          # Core scanning logic
│   ├── ioc/              # IOC definitions and matching
│   ├── hash/             # Hash computation utilities
│   └── report/           # Report generation
├── internal/             # Private packages
├── resources/            # Static resources (ASCII art, etc.)
├── .goreleaser.yaml      # GoReleaser configuration
├── go.mod
├── go.sum
└── README.md
```

### Error Handling
- Return errors rather than panicking
- Wrap errors with context using `fmt.Errorf` with `%w`
- Handle platform-specific errors gracefully

### Cross-Platform Considerations
- Use `filepath` package for path operations (not `path`)
- Use `os.PathSeparator` and `os.PathListSeparator` where needed
- Test path handling on all platforms
- Handle line endings appropriately (CRLF vs LF)

## Junie Instructions

### When Making Changes
1. Ensure all changes are pure Go with no CGO dependencies
2. Run tests after code changes: `go test ./...`
3. Verify the code compiles for all target platforms
4. Follow the existing code style in the codebase

### Before Submitting Shai-Hulud-Scanner
1. Run `go fmt ./...` to format code
2. Run `go vet ./...` to check for issues
3. Run `go test ./...` to ensure tests pass
4. Verify no platform-specific code without proper build tags

### Testing Verification
- Always run tests to verify the correctness of proposed solutions
- If tests fail, investigate and fix the issue before submitting
- Add new tests when adding new functionality
