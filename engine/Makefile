.PHONY: test plugin-check plugin-check-openclaw count install clean

# Definition of done touches these gates (the internal design notes).
# The QA suites ship only with the full source tree; in the public export
# the gated targets SKIP loudly (see engine/PUBLISHED_FROM).

test:
	@if [ ! -d tests ]; then \
		echo "SKIP: tests/ is not part of this export (see engine/PUBLISHED_FROM)"; \
		exit 0; \
	fi
	python3 -m unittest discover -s tests -v

plugin-check:
	@if ! ls host/opencode/*.test.ts >/dev/null 2>&1; then \
		echo "SKIP: adapter tests are not part of this export (see engine/PUBLISHED_FROM)"; \
		exit 0; \
	fi
	cd host/opencode && bun test

plugin-check-openclaw:
	@if ! ls host/openclaw/*.test.ts >/dev/null 2>&1; then \
		echo "SKIP: adapter tests are not part of this export (see engine/PUBLISHED_FROM)"; \
		exit 0; \
	fi
	cd host/openclaw && bun test

count:
	@find babayaga $(wildcard tests) -name '*.py' | xargs wc -l | tail -1
	@find host/opencode -name '*.ts' ! -name '*.test.ts' | xargs wc -l | tail -1

install:
	uv venv .venv
	.venv/bin/pip install -e .

clean:
	rm -rf .venv build dist *.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
