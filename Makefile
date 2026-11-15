.PHONY: install test lint package api self-scan kb-bootstrap

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest

lint:
	python -m ruff check .
	python -m ruff format --check src tests
	python -m mypy src/sentinel

package:
	python -m build

api:
	sentinel api

self-scan:
	sentinel scan . --through module1 --output artifacts/self-scan.json

kb-bootstrap:
	python scripts/build_vulnerability_graph.py

