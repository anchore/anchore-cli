############################################################
# Makefile for the Anchore CLI, a simple command line interface to the
# Anchore Engine service. The rules, directives, and variables in this
# Makefile enable testing, Docker image generation, and pushing Docker
# images.
############################################################


#### Docker Hub, git repos
############################################################
DEV_IMAGE_REPO := robertprince/anchore-cli-dev
PROD_IMAGE_REPO := robertprince/anchore-cli
TEST_INFRA_REPO_URL := https://github.com/robertp/test-infra.git


#### CircleCI environment variables
############################################################
export VERBOSE ?= false
export CI ?= false
export DOCKER_PASS ?=
export DOCKER_USER ?=
export LATEST_RELEASE_BRANCH ?=
export PROD_IMAGE_REPO ?=
export RELEASE_BRANCHES ?=

# Use $CIRCLE_BRANCH if it's set, otherwise use current HEAD branch
GIT_BRANCH := $(shell echo $${CIRCLE_BRANCH:=$$(git rev-parse --abbrev-ref HEAD)})

# Use $CIRCLE_PROJECT_REPONAME if it's set, otherwise the git project top level dir name
GIT_REPO := $(shell echo $${CIRCLE_PROJECT_REPONAME:=$$(basename `git rev-parse --show-toplevel`)})
TEST_IMAGE_NAME := $(GIT_REPO):dev

# Use $CIRCLE_SHA if it's set, otherwise use SHA from HEAD
COMMIT_SHA := $(shell echo $${CIRCLE_SHA:=$$(git rev-parse HEAD)})

# Use $CIRCLE_TAG if it's set
GIT_TAG ?= $(shell echo $${CIRCLE_TAG:=null})

# TODO set the kind cluster name in the test-infra container
# instead of passing it in from here; the context is well
# known from the caller (this code) so it doesn't need to
# be explicitly labeled also by the caller
CLUSTER_NAME := e2e-testing


# Environment configuration for make
############################################################
SHELL := /usr/bin/env bash
VENV := venv
ACTIVATE_VENV := source $(VENV)/bin/activate
PYTHON := $(VENV)/bin/python3
CI_USER := circleci

# Running make will invoke the help target
.DEFAULT_GOAL := help

# Run make serially. Note that recursively invoked make will still
# run recipes in parallel (unless they also contain .NOTPARALLEL)
.NOTPARALLEL:

# Specify the Docker image to use in CI commands
# CI_RUNNER_IMAGE := docker.io/anchore/test-infra:python36
CI_RUNNER_IMAGE := test-infra:python36

CI_CMD = anchore-ci/local_ci

# If running in CI, make is invoked from the test-infra container, so run commands directly
ifeq ($(CI), true)
  CI_CMD := /anchore-ci/local_ci
  RUN_CMD := $(CI_CMD)
else
  RUN_CMD = $(SHELL)
endif


#### Make targets
############################################################

.PHONY: all venv install install-dev lint build cluster-up cluster-down
.PHONY: test-unit test-functional test-e2e run-test-e2e test push push-dev push-rc
.PHONY: push-prod push-rebuild dist-deb dist-rpm dist-mac clean printvars help

all: VERBOSE := true ## Run Anchore CLI full CI pipeline locally (lint, build, test, push)
all: lint build test push

anchore-ci: ## Fetch test artifacts for local CI
	git clone $(TEST_INFRA_REPO_URL) /tmp/test-infra
	rm -rf ./anchore-ci && mv /tmp/test-infra/anchore-ci . && rm -rf /tmp/test-infra

venv: $(VENV)/bin/activate ## Set up a virtual environment
$(VENV)/bin/activate:
	python3 -m venv $(VENV)

install: venv setup.py requirements.txt ## Install to virtual environment
	@$(ACTIVATE_VENV) && $(PYTHON) setup.py install

install-dev: venv setup.py requirements.txt ## Install to virtual environment in editable mode
	@$(ACTIVATE_VENV) && $(PYTHON) -m pip install --editable .

lint: venv anchore-ci ## Lint code (currently using flake8)
	@$(ACTIVATE_VENV) && $(CI_CMD) lint $(PYTHON)

# Local CI script
build: Dockerfile ## Build dev Anchore CLI Docker image
	@$(RUN_CMD) scripts/ci/build $(COMMIT_SHA) $(GIT_REPO) $(TEST_IMAGE_NAME)

cluster-up: anchore-ci ## Bring up a kind (Kubernetes IN Docker) cluster to use for testing
cluster-up: CLUSTER_CONFIG := test/e2e/kind-config.yaml
cluster-up: KUBERNETES_VERSION := 1.15.7
cluster-up: test/e2e/kind-config.yaml
	$(CI_CMD) install-cluster-deps $(VENV)
	$(CI_CMD) cluster-up $(CLUSTER_NAME) $(CLUSTER_CONFIG) $(KUBERNETES_VERSION)

cluster-down: anchore-ci ## Tear down/shut down the kind cluster
	$(CI_CMD) cluster-down $(CLUSTER_NAME)

test-unit: anchore-ci venv ## Run unit tests (tox)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-unit $(PYTHON)

test-functional: anchore-ci venv ## Run functional tests (tox)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-functional $(PYTHON)

# Local CI script
test-e2e: anchore-ci cluster-up ## Set up and run end to end tests
	$(ACTIVATE_VENV) && $(CI_CMD) setup-e2e-tests $(COMMIT_SHA) $(DEV_IMAGE_REPO) $(GIT_TAG) $(TEST_IMAGE_NAME)
	@$(MAKE) run-test-e2e
	@$(MAKE) cluster-down

# Local CI script
run-test-e2e: venv
	$(ACTIVATE_VENV) && $(RUN_CMD) scripts/ci/e2e-tests $(PYTHON)

test: ## Run all tests: unit, functional, and e2e
	@$(MAKE) test-unit
	@$(MAKE) test-functional
	@$(MAKE) test-e2e

push: anchore-ci push-dev ## Push dev Anchore CLI Docker image to Docker Hub
push-dev:
	@$(CI_CMD) push-dev-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

push-rc: anchore-ci ## Push RC Anchore CLI Docker image to Docker Hub (not available outside of CI)
	@$(CI_CMD) push-rc-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

push-prod: anchore-ci ## Push release Anchore CLI Docker image to Docker Hub (not available outside of CI)
	@$(CI_CMD) push-prod-image-release "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)" "$(PROD_IMAGE_REPO)"

push-rebuild: anchore-ci ## Rebuild and push prod Anchore CLI docker image to DOcker Hub (not available outside of CI)
	@$(CI_CMD) push-prod-image-rebuild "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)" "$(PROD_IMAGE_REPO)"

dist-deb: ## Package Anchore CLI for Debian-based distros
	@$(RUN_CMD) scripts/make-dpkg.sh

dist-mac: ## Package Anchore CLI for MacOS
	@$(RUN_CMD) scripts/make-macos-bin.sh

dist-rpm: ## Package Anchore CLI for RH-based distros
	@$(RUN_CMD) scripts/make-rpm.sh

clean: anchore-ci ## Clean up the project directory and delete dev image
	@$(CI_CMD) clean $(TEST_IMAGE_NAME)

printvars: ## Print make variables
	@$(foreach V,$(sort $(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $V)),$(warning $V=$($V) ($(value $V)))))

help: ## Show this usage message
	@printf "\n%s\n\n" "usage: make <target>"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'
