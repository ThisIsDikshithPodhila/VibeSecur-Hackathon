.DEFAULT_GOAL := help
.NOTPARALLEL:
PYTHON ?= .venv/bin/python
ARTIFACTS ?= artifacts/gates

.PHONY: help test contracts api ui-build evaluate gate-laya gate-boundary gate-repair
help:
	@echo 'test / contracts: light checks; api: trusted backend; ui-build: remote build'
	@echo 'evaluate TREATMENT=baseline|deterministic|deterministic_laya'
	@echo 'gate-laya: remote model inference; gate-boundary / gate-repair: CONFIG required'
	@echo 'Run one heavy gate at a time on the demo VM. See README.md.'

test:
	VIBESECUR_LAYA_ENABLED=0 $(PYTHON) -m pytest -q

contracts:
	$(PYTHON) scripts/gate_laya.py --mode contract --output $(ARTIFACTS)/laya-contract.json
	$(PYTHON) scripts/gate_repair.py --mode contract

api:
	$(PYTHON) -m uvicorn vibesecur.api:create_app --factory --host 0.0.0.0 --port 8000

ui-build:
	npm --prefix apps/presenter ci
	npm --prefix apps/presenter run build

evaluate:
	test -n "$(TREATMENT)"
	$(PYTHON) scripts/evaluate.py $(TREATMENT) --output evaluations/reports/$(TREATMENT)-current.json

gate-laya:
	$(PYTHON) scripts/gate_laya.py --mode infer --output $(ARTIFACTS)/laya-suitability.json

gate-boundary:
	test -n "$(CONFIG)"
	$(PYTHON) scripts/gate_boundary.py --config "$(CONFIG)" --output $(ARTIFACTS)/boundary.json

gate-repair:
	test -n "$(CONFIG)"
	$(PYTHON) scripts/gate_repair.py --mode repair --config "$(CONFIG)" --output $(ARTIFACTS)/repair.json
