.PHONY: help build release test clean install run dev fmt lint check docs setup-dev setup-cluster benchmark health-check docker-build docker-up docker-down

# Configuration
BINARY_NAME = uploader
INSTALL_PATH = /usr/local/bin
CONFIG_PATH = /etc/uploader
DATA_PATH = /var/lib/uploader

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

# Default target
.DEFAULT_GOAL := help

## help: Display this help message
help:
	@echo "$(BLUE)Available targets:$(NC)"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | column -t -s ':'
	@echo ""

## build: Build debug binary
build:
	@echo "$(BLUE)Building debug binary...$(NC)"
	cargo build
	@echo "$(GREEN)✓ Build complete: ./target/debug/$(BINARY_NAME)$(NC)"

## release: Build optimized release binary
release:
	@echo "$(BLUE)Building release binary...$(NC)"
	cargo build --release
	@echo "$(GREEN)✓ Release build complete: ./target/release/$(BINARY_NAME)$(NC)"

## test: Run all tests
test:
	@echo "$(BLUE)Running tests...$(NC)"
	cargo test
	@echo "$(GREEN)✓ Tests passed$(NC)"

## test-verbose: Run tests with verbose output
test-verbose:
	@echo "$(BLUE)Running tests (verbose)...$(NC)"
	cargo test -- --nocapture

## clean: Remove build artifacts
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	cargo clean
	rm -rf node*/
	rm -rf storage/
	rm -rf benchmark-results/
	@echo "$(GREEN)✓ Clean complete$(NC)"

## fmt: Format code with rustfmt
fmt:
	@echo "$(BLUE)Formatting code...$(NC)"
	cargo fmt
	@echo "$(GREEN)✓ Code formatted$(NC)"

## lint: Run clippy linter
lint:
	@echo "$(BLUE)Running clippy...$(NC)"
	cargo clippy -- -D warnings
	@echo "$(GREEN)✓ Linting complete$(NC)"

## check: Check code without building
check:
	@echo "$(BLUE)Checking code...$(NC)"
	cargo check
	@echo "$(GREEN)✓ Check complete$(NC)"

## fix: Auto-fix code issues
fix:
	@echo "$(BLUE)Auto-fixing code issues...$(NC)"
	cargo fix --allow-dirty
	cargo fmt
	@echo "$(GREEN)✓ Auto-fix complete$(NC)"

## install: Install binary to system (requires sudo)
install: release
	@echo "$(BLUE)Installing $(BINARY_NAME)...$(NC)"
	sudo mkdir -p $(INSTALL_PATH)
	sudo cp target/release/$(BINARY_NAME) $(INSTALL_PATH)/
	sudo chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "$(GREEN)✓ Installed to $(INSTALL_PATH)/$(BINARY_NAME)$(NC)"

## uninstall: Remove binary from system (requires sudo)
uninstall:
	@echo "$(YELLOW)Uninstalling $(BINARY_NAME)...$(NC)"
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "$(GREEN)✓ Uninstalled$(NC)"

## install-service: Install as systemd service (requires sudo)
install-service: release
	@echo "$(BLUE)Installing systemd service...$(NC)"
	@chmod +x scripts/install-systemd.sh
	@sudo scripts/install-systemd.sh

## uninstall-service: Uninstall systemd service (requires sudo)
uninstall-service:
	@echo "$(YELLOW)Uninstalling systemd service...$(NC)"
	@chmod +x scripts/uninstall-systemd.sh
	@sudo scripts/uninstall-systemd.sh

## install-autoupload-service: Install auto upload daemon as systemd service (usage: make install-autoupload-service USER=dev)
install-autoupload-service: release
	@if [ -z "$(USER)" ]; then \
		echo "$(RED)Error: USER is required$(NC)"; \
		echo "Usage: make install-autoupload-service USER=dev"; \
		exit 1; \
	fi
	@echo "$(BLUE)Installing auto upload systemd service...$(NC)"
	@chmod +x scripts/install-autoupload-systemd.sh
	@sudo scripts/install-autoupload-systemd.sh $(USER)

## uninstall-autoupload-service: Uninstall auto upload daemon systemd service (requires sudo)
uninstall-autoupload-service:
	@echo "$(YELLOW)Uninstalling auto upload systemd service...$(NC)"
	@chmod +x scripts/uninstall-autoupload-systemd.sh
	@sudo scripts/uninstall-autoupload-systemd.sh

## autoupload-status: Show auto upload service status
autoupload-status:
	@sudo systemctl status uploader-autoupload.service || true

## autoupload-start: Start auto upload service
autoupload-start:
	@echo "$(BLUE)Starting auto upload service...$(NC)"
	@sudo systemctl start uploader-autoupload.service
	@echo "$(GREEN)✓ Auto upload service started$(NC)"

## autoupload-stop: Stop auto upload service
autoupload-stop:
	@echo "$(YELLOW)Stopping auto upload service...$(NC)"
	@sudo systemctl stop uploader-autoupload.service
	@echo "$(GREEN)✓ Auto upload service stopped$(NC)"

## autoupload-restart: Restart auto upload service
autoupload-restart:
	@echo "$(BLUE)Restarting auto upload service...$(NC)"
	@sudo systemctl restart uploader-autoupload.service
	@echo "$(GREEN)✓ Auto upload service restarted$(NC)"

## autoupload-logs: View auto upload service logs
autoupload-logs:
	@sudo journalctl -u uploader-autoupload.service -f

## setup-multi: Setup multiple instances (usage: make setup-multi NUM=3 PORT=50051)
setup-multi: release
	@if [ -z "$(NUM)" ]; then \
		echo "$(RED)Error: NUM is required$(NC)"; \
		echo "Usage: make setup-multi NUM=3 PORT=50051"; \
		exit 1; \
	fi
	@echo "$(BLUE)Setting up $(NUM) instances...$(NC)"
	@chmod +x scripts/setup-multi-instance.sh
	@sudo scripts/setup-multi-instance.sh $(NUM) $(PORT)

## service-status: Show systemd service status
service-status:
	@sudo systemctl status uploader.service || true
	@echo ""
	@sudo systemctl status 'uploader@*' || true

## service-start: Start systemd service
service-start:
	@echo "$(BLUE)Starting service...$(NC)"
	@sudo systemctl start uploader.service
	@echo "$(GREEN)✓ Service started$(NC)"

## service-stop: Stop systemd service
service-stop:
	@echo "$(YELLOW)Stopping service...$(NC)"
	@sudo systemctl stop uploader.service
	@echo "$(GREEN)✓ Service stopped$(NC)"

## service-restart: Restart systemd service
service-restart:
	@echo "$(BLUE)Restarting service...$(NC)"
	@sudo systemctl restart uploader.service
	@echo "$(GREEN)✓ Service restarted$(NC)"

## service-logs: View systemd service logs
service-logs:
	@sudo journalctl -u uploader.service -f

## service-debug: Enable debug logging for systemd service
service-debug:
	@echo "$(BLUE)Enabling debug logging for uploader service...$(NC)"
	@sudo mkdir -p /etc/systemd/system/uploader.service.d
	@echo '[Service]' | sudo tee /etc/systemd/system/uploader.service.d/debug.conf > /dev/null
	@echo 'Environment="RUST_LOG=debug"' | sudo tee -a /etc/systemd/system/uploader.service.d/debug.conf > /dev/null
	@echo 'Environment="RUST_BACKTRACE=1"' | sudo tee -a /etc/systemd/system/uploader.service.d/debug.conf > /dev/null
	@sudo systemctl daemon-reload
	@sudo systemctl restart uploader
	@echo "$(GREEN)✓ Debug logging enabled - service restarted$(NC)"
	@echo "$(YELLOW)View logs with: make service-logs$(NC)"

## service-debug-stop: Disable debug logging for systemd service
service-debug-stop:
	@echo "$(YELLOW)Disabling debug logging for uploader service...$(NC)"
	@sudo rm -f /etc/systemd/system/uploader.service.d/debug.conf
	@sudo systemctl daemon-reload
	@sudo systemctl restart uploader
	@echo "$(GREEN)✓ Debug logging disabled - service restarted$(NC)"

## run: Run debug binary as server
run: build
	@echo "$(BLUE)Starting server (debug mode)...$(NC)"
	./target/debug/$(BINARY_NAME) server

## run-release: Run release binary as server
run-release: release
	@echo "$(BLUE)Starting server (release mode)...$(NC)"
	./target/release/$(BINARY_NAME) server

## dev: Run with auto-reload on file changes (requires cargo-watch)
dev:
	@which cargo-watch > /dev/null || (echo "$(RED)cargo-watch not found. Install with: cargo install cargo-watch$(NC)" && exit 1)
	@echo "$(BLUE)Starting development server with auto-reload...$(NC)"
	cargo watch -x 'run -- server'

## init-config: Generate default configuration file
init-config: build
	@echo "$(BLUE)Generating default configuration...$(NC)"
	./target/debug/$(BINARY_NAME) init-config
	@echo "$(GREEN)✓ Configuration created: config.toml$(NC)"

## gen-cert: Generate certificate (usage: make gen-cert NAME=node1 ADDR=192.168.1.100:50051)
gen-cert: build
	@if [ -z "$(NAME)" ] || [ -z "$(ADDR)" ]; then \
		echo "$(RED)Error: NAME and ADDR are required$(NC)"; \
		echo "Usage: make gen-cert NAME=node1 ADDR=192.168.1.100:50051"; \
		exit 1; \
	fi
	@echo "$(BLUE)Generating certificate...$(NC)"
	./target/debug/$(BINARY_NAME) gen-cert \
		--name $(NAME) \
		--address $(ADDR)
	@echo "$(GREEN)✓ Certificate generated: node.crt, node.key$(NC)"

## setup-dev: Setup development environment
setup-dev:
	@echo "$(BLUE)Setting up development environment...$(NC)"
	@which protoc > /dev/null || (echo "$(RED)protoc not found. Install Protocol Buffers compiler first.$(NC)" && exit 1)
	cargo install cargo-watch || true
	cargo install cargo-edit || true
	rustup component add rustfmt clippy
	@echo "$(GREEN)✓ Development environment ready$(NC)"

## setup-cluster: Setup local 3-node cluster for testing
setup-cluster: release
	@echo "$(BLUE)Setting up local cluster...$(NC)"
	chmod +x scripts/setup-cluster.sh
	./scripts/setup-cluster.sh
	@echo "$(GREEN)✓ Cluster setup complete$(NC)"
	@echo "$(YELLOW)Start nodes with:$(NC)"
	@echo "  make start-cluster"

## start-cluster: Start all cluster nodes in background
start-cluster:
	@echo "$(BLUE)Starting cluster nodes...$(NC)"
	@for i in 1 2 3; do \
		echo "Starting node-$$i..."; \
		nohup ./target/release/$(BINARY_NAME) --config node$$i/config.toml server > node$$i/node.log 2>&1 & \
		echo $$! > node$$i/node.pid; \
	done
	@sleep 2
	@echo "$(GREEN)✓ Cluster started$(NC)"
	@echo "$(YELLOW)Check logs: tail -f node1/node.log$(NC)"

## stop-cluster: Stop all cluster nodes
stop-cluster:
	@echo "$(YELLOW)Stopping cluster nodes...$(NC)"
	@for i in 1 2 3; do \
		if [ -f node$$i/node.pid ]; then \
			kill $$(cat node$$i/node.pid) 2>/dev/null || true; \
			rm node$$i/node.pid; \
			echo "Stopped node-$$i"; \
		fi \
	done
	@pkill -f "uploader.*server" || true
	@echo "$(GREEN)✓ Cluster stopped$(NC)"

## upload-test: Test upload to local server (usage: make upload-test FILE=test.txt)
upload-test: release
	@if [ -z "$(FILE)" ]; then \
		echo "$(RED)Error: FILE is required$(NC)"; \
		echo "Usage: make upload-test FILE=test.txt"; \
		exit 1; \
	fi
	@echo "$(BLUE)Uploading $(FILE)...$(NC)"
	./target/release/$(BINARY_NAME) upload \
		--file $(FILE) \
		--servers 127.0.0.1:50051
	@echo "$(GREEN)✓ Upload complete$(NC)"

## list-files: List files on local server
list-files: release
	@echo "$(BLUE)Listing files...$(NC)"
	./target/release/$(BINARY_NAME) list \
		--server 127.0.0.1:50051

## ping: Ping local server
ping: release
	@echo "$(BLUE)Pinging server...$(NC)"
	./target/release/$(BINARY_NAME) ping \
		--server 127.0.0.1:50051

## benchmark: Run performance benchmarks
benchmark: release
	@echo "$(BLUE)Running benchmarks...$(NC)"
	chmod +x scripts/benchmark.sh
	./scripts/benchmark.sh suite

## benchmark-quick: Run quick benchmark test
benchmark-quick: release
	@echo "$(BLUE)Running quick benchmark...$(NC)"
	chmod +x scripts/benchmark.sh
	./scripts/benchmark.sh upload 10 3

## health-check: Start health monitoring
health-check: release
	@echo "$(BLUE)Starting health monitor...$(NC)"
	chmod +x scripts/health-monitor.sh
	./scripts/health-monitor.sh

## backup-sync: Start backup sync service
backup-sync: release
	@echo "$(BLUE)Starting backup sync...$(NC)"
	chmod +x scripts/backup-sync.sh
	mkdir -p uploads
	./scripts/backup-sync.sh

## docker-build: Build Docker image
docker-build:
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -t uploader:latest .
	@echo "$(GREEN)✓ Docker image built$(NC)"

## docker-up: Start Docker containers
docker-up:
	@echo "$(BLUE)Starting Docker containers...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✓ Containers started$(NC)"

## docker-down: Stop Docker containers
docker-down:
	@echo "$(YELLOW)Stopping Docker containers...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Containers stopped$(NC)"

## docker-logs: View Docker container logs
docker-logs:
	docker-compose logs -f

## docs: Generate and open documentation
docs:
	@echo "$(BLUE)Generating documentation...$(NC)"
	cargo doc --no-deps --open
	@echo "$(GREEN)✓ Documentation generated$(NC)"

## size: Show binary sizes
size:
	@echo "$(BLUE)Binary sizes:$(NC)"
	@if [ -f target/debug/$(BINARY_NAME) ]; then \
		echo "Debug:   $$(du -h target/debug/$(BINARY_NAME) | cut -f1)"; \
	fi
	@if [ -f target/release/$(BINARY_NAME) ]; then \
		echo "Release: $$(du -h target/release/$(BINARY_NAME) | cut -f1)"; \
	fi

## deps: Show dependency tree
deps:
	@echo "$(BLUE)Dependency tree:$(NC)"
	cargo tree

## update: Update dependencies
update:
	@echo "$(BLUE)Updating dependencies...$(NC)"
	cargo update
	@echo "$(GREEN)✓ Dependencies updated$(NC)"

## audit: Run security audit
audit:
	@echo "$(BLUE)Running security audit...$(NC)"
	@which cargo-audit > /dev/null || cargo install cargo-audit
	cargo audit
	@echo "$(GREEN)✓ Audit complete$(NC)"

## all: Build, test, and lint
all: fmt lint test release
	@echo "$(GREEN)✓ All checks passed$(NC)"

## watch-test: Watch and run tests on file changes
watch-test:
	@which cargo-watch > /dev/null || (echo "$(RED)cargo-watch not found. Run: cargo install cargo-watch$(NC)" && exit 1)
	cargo watch -x test

## coverage: Generate test coverage report (requires cargo-tarpaulin)
coverage:
	@which cargo-tarpaulin > /dev/null || (echo "$(RED)cargo-tarpaulin not found. Run: cargo install cargo-tarpaulin$(NC)" && exit 1)
	@echo "$(BLUE)Generating coverage report...$(NC)"
	cargo tarpaulin --out Html --output-dir coverage
	@echo "$(GREEN)✓ Coverage report: coverage/index.html$(NC)"

## version: Show version information
version:
	@echo "$(BLUE)Version Information:$(NC)"
	@echo "Uploader: $$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)"
	@echo "Rust:     $$(rustc --version | cut -d' ' -f2)"
	@echo "Cargo:    $$(cargo --version | cut -d' ' -f2)"

## info: Display project information
info:
	@echo "$(BLUE)Project Information:$(NC)"
	@echo "Name:        $(BINARY_NAME)"
	@echo "Binary:      ./target/release/$(BINARY_NAME)"
	@echo "Config:      config.toml"
	@echo "Storage:     ./storage"
	@echo "Scripts:     ./scripts"
	@echo ""
	@echo "$(BLUE)Quick Commands:$(NC)"
	@echo "make release      - Build optimized binary"
	@echo "make run-release  - Run the server"
	@echo "make setup-cluster - Setup test cluster"
	@echo "make all          - Full build & test"

## update-and-deploy: Update code, build, and deploy with debug logging
update-and-deploy:
	@echo "$(BLUE)🔄 Starting update and deployment process...$(NC)"
	@echo "$(YELLOW)📥 Updating from git...$(NC)"
	git pull origin main
	@echo "$(YELLOW)🔨 Building release binary...$(NC)"
	$(MAKE) release
	@echo "$(YELLOW)⏹️  Stopping service...$(NC)"
	$(MAKE) service-stop
	@echo "$(YELLOW)📦 Deploying new binary...$(NC)"
	sudo cp ./target/release/uploader /usr/local/bin/uploader
	@echo "$(YELLOW)🚫 Stopping debug mode...$(NC)"
	$(MAKE) service-debug-stop
	@echo "$(YELLOW)🔄 Restarting service...$(NC)"
	$(MAKE) service-restart
	@echo "$(YELLOW)📋 Showing service logs...$(NC)"
	$(MAKE) service-logs
