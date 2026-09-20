.PHONY: check test lint typecheck format build
check: test lint typecheck

test:
	python -m pytest --cov=dam --cov-report=term-missing

lint:
	python -m ruff check .
	python -m ruff format --check .

typecheck:
	python -m mypy src

format:
	python -m ruff check --fix .
	python -m ruff format .

build:
	python -m build
