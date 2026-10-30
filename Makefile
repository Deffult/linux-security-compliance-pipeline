.PHONY: help test lint audit report plan docker docker-audit gate
IMAGE ?= mrdeffult/linux-security-audit:dev

help:
	@echo "make test | lint | audit | report | plan | docker | docker-audit | gate"

test:
	python3 -m pytest -q

lint:
	ruff check audit scripts tests && shellcheck audit/hardening.sh

audit:            ## console audit of this host (use sudo for full coverage)
	python3 audit/linux_audit.py --fail-on high

report:           ## JSON + HTML report in ./reports
	python3 audit/linux_audit.py --json reports/audit.json --html reports/audit.html --fail-on none

plan:             ## show hardening changes without applying them
	bash audit/hardening.sh plan

docker:
	docker build -t $(IMAGE) .

docker-audit: docker  ## audit the host through the container (read-only mount)
	docker run --rm --user 0:0 --net=host --pid=host -v /:/host:ro $(IMAGE) \
	  --root /host --network on --fail-on high

gate:             ## evaluate scanner reports in ./reports against policy/gate-policy.json
	python3 scripts/security_gate.py
