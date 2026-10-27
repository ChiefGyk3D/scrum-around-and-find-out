# SPDX-License-Identifier: Apache-2.0
# Everything CI runs, runnable here. `make check` is the pipeline minus the version matrix.
# Capture its exit code before you trust it:   make check > check.log 2>&1; echo "exit=$$?"

PY ?= .venv/bin/python
BIN := $(dir $(PY))

.PHONY: help venv lint format typecheck test generated claude-gitlinks check build clean

help:
	@echo "make venv       - create .venv from the hash-pinned dev lock and install safo editable"
	@echo "make lint       - ruff check and ruff format --check"
	@echo "make format     - apply ruff format"
	@echo "make typecheck  - mypy --strict over src and tests"
	@echo "make test       - pytest (loopback only; see tests/conftest.py)"
	@echo "make generated  - the generated files match agents.yaml, and the profiles verify"
	@echo "make claude-gitlinks - fail on a gitlink under .claude/ or an unignored .claude/worktrees/"
	@echo "make check      - lint, typecheck, test, generated and claude-gitlinks: run before pushing"
	@echo "make build      - sdist and wheel"

venv:
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install --require-hashes -r requirements-dev.txt
	$(PY) -m pip install --no-deps -e .

lint:
	$(BIN)ruff check .
	$(BIN)ruff format --check .

format:
	$(BIN)ruff format .

typecheck:
	$(BIN)mypy

test:
	$(BIN)pytest -n auto

# the same drift checks the test suite runs, named so a failure says which generated file is stale
generated:
	$(PY) scripts/gen_routing.py --check
	$(PY) scripts/gen_profiles.py --check
	$(BIN)safo profiles verify --agents agents.yaml

# an agent worktree staged as an embedded repository (#86)
claude-gitlinks:
	bash scripts/check-claude-gitlinks.sh --require-ignore

check: lint typecheck test generated claude-gitlinks

build:
	$(PY) -m build

clean:
	rm -rf build dist src/*.egg-info .pytest_cache .ruff_cache .mypy_cache .coverage coverage.xml
