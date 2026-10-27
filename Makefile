.PHONY: help install test coverage lint clean scan

help:
	@echo "Web Guard development tasks"
	@echo "  make install   Install the package in editable mode with development tools"
	@echo "  make test      Run the automated test suite"
	@echo "  make coverage  Run tests with a coverage report"
	@echo "  make clean     Remove caches, build artefacts and temporary files"
	@echo "  make scan      Run a local audit, for example: make scan URL=https://example.com"

install:
	python3 -m pip install -e ".[dev]"

test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider

coverage:
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider --cov=web_guard --cov-report=term-missing

lint:
	python3 -m ruff check --no-cache src tests

clean:
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -type f -name "*.py[co]" -delete
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov coverage.xml build dist *.egg-info
	rm -f web-guard-report-*.md web-guard-report-*.json
