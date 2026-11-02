PYTHON ?= .venv/bin/python
DATA := data/processed/synthetic_events.parquet
MODEL := artifacts/scorer.joblib
# Extra privguard.demo flags, e.g. make demo DEMO_ARGS="--speed 0"
DEMO_ARGS ?=

.PHONY: venv install data lanl train evaluate test lint api dashboard demo up down demo-docker site clean

venv:
	python3.11 -m venv .venv

install: venv
	$(PYTHON) -m pip install -e ".[ml,api,dashboard,dev]"

# File targets: data and model are only rebuilt when missing or older than config.toml.
data: $(DATA)
$(DATA): config.toml
	$(PYTHON) -m privguard.synthetic

train: $(MODEL)
$(MODEL): $(DATA) config.toml
	$(PYTHON) -m privguard.scorer

lanl:
	$(PYTHON) -m privguard.lanl

evaluate: $(DATA)
	$(PYTHON) -m privguard.evaluate

test: $(DATA)
	$(PYTHON) -m pytest --cov=privguard --cov-report=term-missing

lint:
	$(PYTHON) -m ruff check src tests

api: $(MODEL)
	$(PYTHON) -m uvicorn privguard.api:app --port 8000

dashboard:
	$(PYTHON) -m streamlit run src/privguard/dashboard.py --server.port 8501

# Local, no Docker: fresh API (+ dashboard) in the background, replay the attack, stop everything on exit.
demo: $(MODEL)
	PYTHON=$(PYTHON) scripts/demo.sh $(DEMO_ARGS)

up:
	docker compose up --build -d --wait

down:
	docker compose down

# Same demo against the compose stack. Starts from an empty alert store (drops the stack's volume).
demo-docker:
	docker compose down -v
	docker compose up --build -d --wait
	docker compose exec api python -m privguard.demo $(DEMO_ARGS)

# Static showcase (GitHub Pages): real model output for the demo scenario + committed plots/screenshots.
# Preview: python -m http.server -d site 8080
site: $(MODEL)
	$(PYTHON) -m privguard.export_site
	mkdir -p site/img && cp reports/synthetic/pr_curves.png docs/screenshots/*.png site/img/

clean:
	rm -rf $(DATA) artifacts data/*.db site/data site/img .pytest_cache .ruff_cache .coverage htmlcov
	find . -name __pycache__ -not -path "./.venv/*" -prune -exec rm -rf {} +
