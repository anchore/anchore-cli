############################################################
# Makefile for the Anchore CLI, a simple command line interface to the
# Anchore Engine service. The rules, directives, and variables in this
# Makefile enable testing, Docker image generation, and pushing Docker
# images.
############################################################


# Make environment configuration
#############################################

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help # Running make without args will run the help target
.NOTPARALLEL: # Run make serially

# Dockerhub image repo
DEV_IMAGE_REPO = anchore/anchore-cli-dev

# Shared CI scripts
TEST_HARNESS_REPO = https://github.com/anchore/test-infra.git
CI_CMD = anchore-ci/ci_harness

# Python environment
VENV = .venv
ACTIVATE_VENV := . $(VENV)/bin/activate
PYTHON := $(VENV)/bin/python3

# Testing environment
CLUSTER_CONFIG = tests/e2e/kind-config.yaml
CLUSTER_NAME = e2e-testing
K8S_VERSION = 1.19.0
TEST_IMAGE_NAME = $(GIT_REPO):dev


#### CircleCI environment variables
# exported variabled are made available to any script called by this Makefile
############################################################

# declared in .circleci/config.yaml
export LATEST_RELEASE_MAJOR_VERSION ?=
export PROD_IMAGE_REPO ?=

# declared in CircleCI contexts
export DOCKER_USER ?=
export DOCKER_PASS ?=

# declared in CircleCI project environment variables settings
export REDHAT_PASS ?=
export REDHAT_REGISTRY ?=

# automatically set to 'true' by CircleCI runners
export CI ?= false

# Use $CIRCLE_BRANCH if it's set, otherwise use current HEAD branch
GIT_BRANCH := $(shell echo $${CIRCLE_BRANCH:=$$(git rev-parse --abbrev-ref HEAD)})

# Use $CIRCLE_PROJECT_REPONAME if it's set, otherwise the git project top level dir name
GIT_REPO := $(shell echo $${CIRCLE_PROJECT_REPONAME:=$$(basename `git rev-parse --show-toplevel`)})

# Use $CIRCLE_SHA if it's set, otherwise use SHA from HEAD
COMMIT_SHA := $(shell echo $${CIRCLE_SHA:=$$(git rev-parse HEAD)})

# Use $CIRCLE_TAG if it's set, otherwise set to null
GIT_TAG := $(shell echo $${CIRCLE_TAG:=null})


#### Make targets
############################################################

.PHONY: ci
ci: lint build test ## Run full CI pipeline, locally

.PHONY: build
build: Dockerfile anchore-ci venv ## Build dev Anchore CLI Docker image
	@$(CI_CMD) scripts/ci/build "$(COMMIT_SHA)" "$(GIT_REPO)" "$(TEST_IMAGE_NAME)"

.PHONY: install
install: venv setup.py requirements.txt ## Install to virtual environment
	$(ACTIVATE_VENV) && $(PYTHON) setup.py install

.PHONY: install-dev
install-dev: venv setup.py requirements.txt ## Install to virtual environment in editable mode
	$(ACTIVATE_VENV) && $(PYTHON) -m pip install --editable .

.PHONY: lint
lint: venv anchore-ci ## Lint code (currently using flake8)
	@$(ACTIVATE_VENV) && $(CI_CMD) lint

.PHONY: clean
clean: ## Clean everything (with prompts)
	@$(CI_CMD) clean "$(VENV)" "$(TEST_IMAGE_NAME)"

.PHONY: clean-all
clean-all: export NOPROMPT = true
clean-all: ## Clean everything (without prompts)
	@$(CI_CMD) clean "$(VENV)" "$(TEST_IMAGE_NAME)" $(NOPROMPT)


# Testing targets
#####################
.PHONY: test
test: ## Run all tests: unit, functional, and e2e
	@$(MAKE) test-unit
	@$(MAKE) test-functional
	@$(MAKE) setup-and-test-e2e

.PHONY: test-unit
test-unit: anchore-ci venv ## Run unit tests (tox)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-unit

.PHONY: test-functional
test-functional: anchore-ci venv ## Run functional tests (tox)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-functional tests/functional/tox.ini

.PHONY: setup-e2e-tests
setup-e2e-tests: anchore-ci venv ## Start kind cluster and set up end to end tests
	@$(MAKE) cluster-up
	@$(ACTIVATE_VENV) && $(CI_CMD) setup-e2e-tests "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

.PHONY: test-e2e
test-e2e: anchore-ci venv ## Run end to end tests (assuming cluster is running and set up has been run)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-cli

.PHONY: setup-and-test-e2e
setup-and-test-e2e: anchore-ci venv ## Set up and run end to end tests
	@$(MAKE) setup-e2e-tests
	@$(MAKE) test-e2e
	@$(MAKE) cluster-down


# Release targets
######################
.PHONY: push-nightly
push-nightly: setup-test-infra ## Push nightly Anchore Engine Docker image to Docker Hub
	@$(CI_CMD) push-nightly-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

.PHONY: push-dev
push-dev: anchore-ci ## Push dev Anchore CLI Docker image to Docker Hub
	@$(CI_CMD) push-dev-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

.PHONY: push-rc
push-rc: anchore-ci ## (Not available outside of CI) Push RC Anchore CLI Docker image to Docker Hub
	@$(CI_CMD) push-rc-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

.PHONY: push-prod
push-prod: anchore-ci ## (Not available outside of CI) Push release Anchore CLI Docker image to Docker Hub
	@$(CI_CMD) push-prod-image-release "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"

.PHONY: push-rebuild
push-rebuild: anchore-ci ## (Not available outside of CI) Rebuild and push prod Anchore CLI docker image to Docker Hub
	@$(CI_CMD) push-prod-image-rebuild "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"

.PHONY: ironbank-artifacts
ironbank-artifacts: anchore-ci ## (Not available outside of CI) Create and upload ironbank buildblob artifacts
	@$(CI_CMD) create-ironbank-artifacts anchore-cli "$(GIT_TAG)"

# Helper targets
####################
.PHONY: cluster-up
cluster-up: anchore-ci venv ## Stand up/start kind cluster
	@$(CI_CMD) install-cluster-deps "$(VENV)"
	@$(ACTIVATE_VENV) && $(CI_CMD) cluster-up "$(CLUSTER_NAME)" "$(CLUSTER_CONFIG)" "$(K8S_VERSION)"

.PHONY: cluster-down
cluster-down: anchore-ci venv ## Tear down/stop kind cluster
	@$(CI_CMD) install-cluster-deps "$(VENV)"
	@$(ACTIVATE_VENV) && $(CI_CMD) cluster-down "$(CLUSTER_NAME)"

setup-test-infra: /tmp/test-infra ## Fetch anchore/test-infra repo for CI scripts
	cd /tmp/test-infra && git pull
	@$(MAKE) anchore-ci
anchore-ci: /tmp/test-infra/anchore-ci
	rm -rf ./anchore-ci; cp -R /tmp/test-infra/anchore-ci .
/tmp/test-infra/anchore-ci: /tmp/test-infra
/tmp/test-infra:
	git clone $(TEST_HARNESS_REPO) /tmp/test-infra

venv: $(VENV)/bin/activate ## Set up a virtual environment
$(VENV)/bin/activate:
	python3 -m venv $(VENV)

.PHONY: printvars
printvars: ## Print make variables
	@$(foreach V,$(sort $(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $V)),$(warning $V=$($V) ($(value $V)))))

.PHONY: help
help:
	@printf "\n%s\n\n" "usage: make <target>"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'
