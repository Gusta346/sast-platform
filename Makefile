.PHONY: up down test lint

up:
	docker compose up --build

down:
	docker compose down

test:
	python -m pytest --cov=services --cov-report=term-missing

lint:
	python -m compileall -q services
	python -m bandit -r services -x services/dashboard
