.PHONY: install test lint run samples score addon-test bundle deploy

install:            ## install backend dev dependencies
	cd backend && pip install -r requirements-dev.txt

test:               ## run the backend test suite
	cd backend && python -m pytest

lint:               ## static checks
	cd backend && ruff check . ../samples && ruff format --check . ../samples

run:                ## run the backend locally on :8080 (reads backend/.env if present)
	cd backend && set -a && [ -f .env ] && . ./.env; set +a; uvicorn app.main:app --reload --port 8080

samples:            ## regenerate the sample .eml corpus
	python samples/build_samples.py

score:              ## score every sample offline (LOCALE=he for Hebrew explanations)
	cd backend && python -m app.cli --first-contact --org acme.com --locale $${LOCALE:-en} ../samples/*.eml

addon-test:         ## render add-on cards for every sample in a mocked Apps Script runtime
	mkdir -p .tmp && for f in samples/*.eml; do \
	  (cd backend && python -m app.cli --json --first-contact "../$$f") > .tmp/$$(basename $$f .eml).json; \
	  (cd backend && python -m app.cli --json --first-contact --locale he "../$$f") > .tmp/he_$$(basename $$f .eml).json; \
	done
	node addon/test/harness.js .tmp/*.json
	python scripts/bundle_addon.py && MG_ADDON_DIR=addon_bundle node addon/test/harness.js .tmp/*.json > /dev/null

deploy:             ## deploy the backend to Cloud Run (needs PROJECT_ID)
	./scripts/deploy_backend.sh

bundle:             ## one-file add-on for copy-paste install: addon_bundle/MailGuard.gs
	python scripts/bundle_addon.py
