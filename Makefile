PROJECT_NAME := shai-hulud-scanner
CMD_DIR      := ./cmd/scanner
BIN_DIR      := bin
DIST_DIR     := dist

.PHONY: debug test clean release-build fmt vet

all: debug

# Build a local debug binary for the current platform
debug:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(PROJECT_NAME) $(CMD_DIR)

# Run the full test suite
test:
	go test ./...

# Format Go code
fmt:
	go fmt ./...

# Run go vet static analysis
vet:
	go vet ./...

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

# Cross-platform release-style builds using go build
release-build:
	@mkdir -p $(DIST_DIR)
	GOOS=linux   GOARCH=amd64 go build -ldflags "-s -w" -o $(DIST_DIR)/$(PROJECT_NAME)-linux-amd64 $(CMD_DIR)
	GOOS=linux   GOARCH=arm64 go build -ldflags "-s -w" -o $(DIST_DIR)/$(PROJECT_NAME)-linux-arm64 $(CMD_DIR)
	GOOS=darwin  GOARCH=amd64 go build -ldflags "-s -w" -o $(DIST_DIR)/$(PROJECT_NAME)-darwin-amd64 $(CMD_DIR)
	GOOS=darwin  GOARCH=arm64 go build -ldflags "-s -w" -o $(DIST_DIR)/$(PROJECT_NAME)-darwin-arm64 $(CMD_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o $(DIST_DIR)/$(PROJECT_NAME)-windows-amd64.exe $(CMD_DIR)
	GOOS=windows GOARCH=arm64 go build -ldflags "-s -w" -o $(DIST_DIR)/$(PROJECT_NAME)-windows-arm64.exe $(CMD_DIR)
