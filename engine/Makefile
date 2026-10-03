.PHONY: test plugin-check count install clean

# Definition of done touches these gates (the internal design notes).
# The QA suites ship only with the full source tree; in the public export
# the gated targets SKIP loudly (see engine/PUBLISHED_FROM).

test:
	@if [ ! -d tests ]; then \
		echo "SKIP: the private QA suite is not part of this export (see engine/PUBLISHED_FROM)"; \
		exit 0; \
	fi
	python3 -m unittest discover -s tests -v

plugin-check:
	@if ! ls scripts/*.test.ts >/dev/null 2>&1; then \
		echo "SKIP: plugin tests are not part of this export (see engine/PUBLISHED_FROM)"; \
		exit 0; \
	fi
	cd scripts && bun test

count:
	@find core $(wildcard tests) -name '*.py' | xargs wc -l | tail -1
	@find scripts -name '*.ts' ! -name '*.test.ts' | xargs wc -l | tail -1

install:
	@test -x .venv/bin/python || uv venv .venv
	uv pip install --python .venv/bin/python -e .

clean:
	rm -rf .venv build dist *.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
