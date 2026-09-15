DEPLOY_HOST ?= nathan1@100.77.169.69
DEPLOY_PATH ?= /usr/local/bin/quasar

MUSL_TARGET := x86_64-unknown-linux-musl
BIN         := target/$(MUSL_TARGET)/release/quasar
TARGET_BTF  := testdata/btf/ubuntu-6.8.0-139

.PHONY: all build dev run test accept lint vmlinux deps deploy logs soak clean

all: build

## build: the static musl binary that deploys to the server
build: bpf/vmlinux.h
	cargo build --release --target $(MUSL_TARGET)

## dev: a native build for local testing
dev: bpf/vmlinux.h
	cargo build

## run: attach locally and stream events (needs root)
run: dev
	sudo ./target/debug/quasar run

test: bpf/vmlinux.h
	cargo test

## accept: every phase's acceptance criteria against real containers (needs root)
# PHASES=3 make accept  runs just one phase.
PHASES ?=
accept: dev
	sudo QUASAR_TEST_ROOT=1 bash scripts/acceptance.sh $(PHASES)

lint: bpf/vmlinux.h
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

## vmlinux: regenerate bpf/vmlinux.h from the DEPLOYMENT target's BTF.
# Not from this machine's. A header dumped from a newer kernel can name fields
# that 6.8 does not have, and the failure would land on the server at load time
# instead of here.
vmlinux bpf/vmlinux.h: $(TARGET_BTF)
	bpftool btf dump file $(TARGET_BTF) format c > bpf/vmlinux.h

$(TARGET_BTF):
	@echo "missing $@ -- fetch it from the deployment target:"
	@echo "    scp $(DEPLOY_HOST):/sys/kernel/btf/vmlinux $@"
	@echo "Refresh it whenever the server's kernel updates, alongside"
	@echo "scripts/probe-target.sh."
	@false

## deploy: binary, unit and policy to the server, then restart the service
# Policy files are copied, never deleted: removing one is a decision, not a
# side effect of it being absent from this checkout.
deploy: build
	scp $(BIN) $(DEPLOY_HOST):/tmp/quasar
	scp deploy/quasar.service $(DEPLOY_HOST):/tmp/quasar.service
	@test -d policy \
	    && { echo "shipping policy/"; \
	         ssh $(DEPLOY_HOST) 'mkdir -p /tmp/quasar-policy'; \
	         scp policy/*.toml $(DEPLOY_HOST):/tmp/quasar-policy/ 2>/dev/null || true; } \
	    || echo "no policy/ in this checkout -- quasar will observe and alert on nothing"
	ssh -t $(DEPLOY_HOST) 'set -e; \
	    sudo install -m 755 /tmp/quasar $(DEPLOY_PATH); \
	    sudo install -d -m 700 /etc/quasar /etc/quasar/policy; \
	    sudo install -m 644 /tmp/quasar.service /etc/systemd/system/quasar.service; \
	    if [ -d /tmp/quasar-policy ]; then \
	        sudo cp /tmp/quasar-policy/*.toml /etc/quasar/policy/ 2>/dev/null || true; \
	        sudo chmod 600 /etc/quasar/policy/*.toml 2>/dev/null || true; \
	        rm -rf /tmp/quasar-policy; \
	    fi; \
	    rm -f /tmp/quasar /tmp/quasar.service; \
	    sudo systemctl daemon-reload; \
	    sudo systemctl enable --now quasar; \
	    sudo systemctl restart quasar; \
	    sleep 2; sudo systemctl --no-pager --full status quasar'

## logs: follow what the deployed service is saying
logs:
	ssh -t $(DEPLOY_HOST) 'sudo journalctl -u quasar -f'

## soak: ship the overhead benchmark to the server and print how to run it
soak: deploy
	scp scripts/soak.sh $(DEPLOY_HOST):/tmp/soak.sh
	@echo
	@echo "sudo on the server wants a password, so run it yourself:"
	@echo "    ssh -t $(DEPLOY_HOST) 'sudo bash /tmp/soak.sh --minutes 60'"

## deps: report on the build prerequisites
deps:
	@ok=0; \
	for t in clang bpftool cargo; do \
	    command -v $$t >/dev/null 2>&1 \
	        && printf '  yes  %s\n' "$$t" \
	        || { printf '  NO   %s\n' "$$t"; ok=1; }; \
	done; \
	test -f /usr/include/bpf/bpf_helpers.h \
	    && printf '  yes  libbpf headers\n' \
	    || { printf '  NO   libbpf headers (dnf install libbpf-devel)\n'; ok=1; }; \
	ls /usr/lib64/libclang.so* >/dev/null 2>&1 \
	    && printf '  yes  libclang (bindgen)\n' \
	    || { printf '  NO   libclang (dnf install clang-devel)\n'; ok=1; }; \
	rustc --print target-libdir --target $(MUSL_TARGET) >/dev/null 2>&1 \
	    && printf '  yes  rust std for %s\n' "$(MUSL_TARGET)" \
	    || { printf '  NO   rust std for %s (rustup target add %s)\n' "$(MUSL_TARGET)" "$(MUSL_TARGET)"; ok=1; }; \
	test -f $(TARGET_BTF) \
	    && printf '  yes  target BTF blob\n' \
	    || { printf '  NO   %s (see: make %s)\n' "$(TARGET_BTF)" "$(TARGET_BTF)"; ok=1; }; \
	exit $$ok

clean:
	cargo clean
