.PHONY: build install clean test update release

# Build configuration
BINARY_NAME=penhunter
BUILD_DIR=bin
VERSION=1.0.0
GITHUB_REPO=cc1a2b/PenHunter
MAIN_PKG=./cmd/penhunter

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PKG)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Install to user home directory
# Linux/macOS: $HOME/penhunter
# Windows: Run from PowerShell or use manual copy
install: build
	@echo "Installing $(BINARY_NAME) to user home directory..."
	@mkdir -p $(HOME)/penhunter/bin
	@mkdir -p $(HOME)/penhunter/config
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(HOME)/penhunter/bin/
	@cp -r config/* $(HOME)/penhunter/config/ 2>/dev/null || true
	@chmod +x $(HOME)/penhunter/bin/$(BINARY_NAME)
	@echo ""
	@echo "Installation complete!"
	@echo "Add to your PATH: export PATH=\"\$$HOME/penhunter/bin:\$$PATH\""
	@echo "Or create symlink: sudo ln -sf $(HOME)/penhunter/bin/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)"
	@echo ""
	@echo "IMPORTANT: Configure your callback URLs in $(HOME)/penhunter/config/user_config.yaml"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@go clean
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Update dependencies
update:
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

# Build for multiple platforms
release:
	@echo "Building releases for multiple platforms..."
	@mkdir -p $(BUILD_DIR)/release
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/release/$(BINARY_NAME)_linux_amd64 $(MAIN_PKG)
	@GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/release/$(BINARY_NAME)_linux_arm64 $(MAIN_PKG)
	@GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/release/$(BINARY_NAME)_darwin_amd64 $(MAIN_PKG)
	@GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/release/$(BINARY_NAME)_darwin_arm64 $(MAIN_PKG)
	@GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/release/$(BINARY_NAME)_windows_amd64.exe $(MAIN_PKG)
	@echo "Releases built in $(BUILD_DIR)/release/"

# Show version
version:
	@echo "Version: $(VERSION)"

# Help
help:
	@echo "Available targets:"
	@echo "  build     - Build the binary"
	@echo "  install   - Install system-wide"
	@echo "  clean     - Clean build artifacts"
	@echo "  test      - Run tests"
	@echo "  update    - Update dependencies"
	@echo "  release   - Build for multiple platforms"
	@echo "  version   - Show version"
