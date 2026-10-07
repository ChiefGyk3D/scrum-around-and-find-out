# SPDX-License-Identifier: MIT
# Everything CI runs, runnable here. `make check` is the pipeline minus the version matrix.
# Capture its exit code before you trust it:   make check > check.log 2>&1; echo "exit=$$?"

PY ?= .venv/bin/python
BIN := $(dir $(PY))

.PHONY: help venv lint format typecheck test check build clean

help:
	@echo "make venv       - create .venv from the hash-pinned dev lock and install safo editable"
	@echo "make lint       - ruff check and ruff format --check"
	@echo "make format     - apply ruff format"
	@echo "make typecheck  - mypy --strict over src and tests"
	@echo "make test       - pytest (loopback only; see tests/conftest.py)"
	@echo "make check      - lint, typecheck and test: run before pushing"
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
	$(BIN)pytest

check: lint typecheck test

build:
	$(PY) -m build

clean:
	rm -rf build dist src/*.egg-info .pytest_cache .ruff_cache .mypy_cache .coverage coverage.xml
