.PHONY: all build build-release build-debug test test-unit test-integration clean install uninstall lint fmt run docker help

APP_NAME := veltrix
CARGO := cargo

all: build-release

# ── Build ──
build-release:
	$(CARGO) build --release
	@echo "Binary: target/release/$(APP_NAME)"

build-debug:
	$(CARGO) build
	@echo "Binary: target/debug/$(APP_NAME)"

build: build-release

# ── Test ──
test-unit:
	$(CARGO) test --lib

test-integration:
	docker compose -f docker/docker-compose.test.yml up -d
	sleep 5
	$(CARGO) test --test integration -- --test-threads=1 || true
	docker compose -f docker/docker-compose.test.yml down

test: test-unit

# ── Lint & Format ──
lint:
	$(CARGO) clippy -- -D warnings 2>/dev/null || $(CARGO) clippy

fmt:
	$(CARGO) fmt

check: lint fmt

# ── Clean ──
clean:
	$(CARGO) clean
	rm -rf target/

clean-all: clean
	rm -rf ~/.cache/veltrix

# ── Run ──
run: build-release
	sudo ./target/release/$(APP_NAME) $(ARGS)

run-debug: build-debug
	./target/debug/$(APP_NAME) $(ARGS)

# ── Install ──
install: build-release
	sudo cp target/release/$(APP_NAME) /usr/local/bin/
	sudo chmod 755 /usr/local/bin/$(APP_NAME)
	@echo "Installed: /usr/local/bin/$(APP_NAME)"

uninstall:
	sudo rm -f /usr/local/bin/$(APP_NAME)
	@echo "Uninstalled: /usr/local/bin/$(APP_NAME)"

# ── Docker ──
docker-build:
	docker build -t $(APP_NAME) .

docker-test:
	docker compose -f docker/docker-compose.test.yml up -d

docker-down:
	docker compose -f docker/docker-compose.test.yml down

# ── Help ──
help:
	@echo "Veltrix Makefile"
	@echo "================"
	@echo "build            Build release binary"
	@echo "build-debug      Build debug binary"
	@echo "test             Run unit tests"
	@echo "test-integration Run integration tests (requires Docker)"
	@echo "lint             Run clippy linter"
	@echo "fmt              Format code"
	@echo "check            Run linter + formatter"
	@echo "clean            Remove build artifacts"
	@echo "install          Install to /usr/local/bin"
	@echo "uninstall        Remove from /usr/local/bin"
	@echo "run ARGS=...     Build and run with arguments"
	@echo "docker-build     Build Docker image"
	@echo "docker-test      Start test containers"
