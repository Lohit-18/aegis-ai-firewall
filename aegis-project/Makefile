.PHONY: help install test bench calibrate corpus demo run lint clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}'

install:   ## install with dev extras
	pip install -e ".[dev]"

test:      ## run the test suite
	PYTHONPATH=. python3 -m pytest tests/ -q

corpus:    ## regenerate the labelled corpus
	python3 corpus/build_corpus.py

bench: corpus  ## regenerate corpus, evaluate, write bench/report.md
	PYTHONPATH=. python3 bench/evaluate.py

calibrate: ## recompute per-channel thresholds from a target FPR
	PYTHONPATH=. python3 bench/calibrate.py

demo:      ## seven attack scenarios against a mock upstream (no API key)
	@bash demo.sh

run:       ## start the gateway
	PYTHONPATH=. python3 -m aegis.main

lint:      ## ruff
	ruff check aegis tests bench corpus

clean:
	rm -rf data/ .pytest_cache __pycache__ **/__pycache__ bench/results.json
