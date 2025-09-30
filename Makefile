lint:
	poetry run ruff format --check app
	poetry run ruff check --select I app

format:
	poetry run ruff format app
	poetry run ruff check --select I --fix app