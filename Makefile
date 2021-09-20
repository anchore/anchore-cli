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
CONTAINER_TEST_CONFIG = scripts/ci/container-tests.yaml
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

.PHONY: ci build install install-dev
.PHONY: lint clean clean-all test
.PHONY: test-unit test-functional setup-and-test-e2e test-e2e
.PHONY: push-dev push-nightly push-rc push-prod push-rebuild
.PHONY: cluster-up cluster-down
.PHONY: setup-test-infra venv printvars help

ci: lint build test ## Run full CI pipeline, locally

build: Dockerfile anchore-ci venv ## Build dev Anchore CLI Docker image
	@$(CI_CMD) scripts/ci/build "$(COMMIT_SHA)" "$(GIT_REPO)" "$(TEST_IMAGE_NAME)"

install: venv setup.py requirements.txt ## Install to virtual environment
	$(ACTIVATE_VENV) && $(PYTHON) setup.py install

install-dev: venv setup.py requirements.txt ## Install to virtual environment in editable mode
	$(ACTIVATE_VENV) && $(PYTHON) -m pip install --editable .

lint: venv anchore-ci ## Lint code (currently using flake8)
	@$(ACTIVATE_VENV) && $(CI_CMD) lint

clean: ## Clean everything (with prompts)
	@$(CI_CMD) clean "$(VENV)" "$(TEST_IMAGE_NAME)"

clean-all: export NOPROMPT = true
clean-all: ## Clean everything (without prompts)
	@$(CI_CMD) clean "$(VENV)" "$(TEST_IMAGE_NAME)" $(NOPROMPT)


# Testing targets
#####################
test: ## Run all tests: unit, functional, and e2e
	@$(MAKE) test-unit
	@$(MAKE) test-functional
	@$(MAKE) setup-and-test-e2e

test-unit: anchore-ci venv ## Run unit tests (tox)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-unit

test-functional: anchore-ci venv ## Run functional tests (tox)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-functional tests/functional/tox.ini

setup-e2e-tests: anchore-ci venv ## Start kind cluster and set up end to end tests
	@$(MAKE) cluster-up
	@$(ACTIVATE_VENV) && $(CI_CMD) setup-e2e-tests "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

test-e2e: anchore-ci venv ## Run end to end tests (assuming cluster is running and set up has been run)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-cli

setup-and-test-e2e: anchore-ci venv ## Set up and run end to end tests
	@$(MAKE) setup-e2e-tests
	@$(MAKE) test-e2e
	@$(MAKE) cluster-down

PHONY: test-container-dev
test-container-dev: setup-test-infra venv ## CI ONLY Run container-structure-tests on locally built image
	@$(ACTIVATE_VENV) && $(CI_CMD) test-container $(CIRCLE_PROJECT_REPONAME) dev $(CONTAINER_TEST_CONFIG)

.PHONY: test-container-prod
test-container-prod: setup-test-infra venv ## CI ONLY Run container-structure-tests on :latest prod image
	@$(ACTIVATE_VENV) && $(CI_CMD) test-container $(CIRCLE_PROJECT_REPONAME) prod $(CONTAINER_TEST_CONFIG)


# Release targets
######################
push-nightly: setup-test-infra ## Push nightly Anchore Engine Docker image to Docker Hub
	@$(CI_CMD) push-nightly-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

push-dev: anchore-ci ## Push dev Anchore CLI Docker image to Docker Hub
	@$(CI_CMD) push-dev-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

push-rc: anchore-ci ## (Not available outside of CI) Push RC Anchore CLI Docker image to Docker Hub
	@$(CI_CMD) push-rc-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

push-prod: anchore-ci ## (Not available outside of CI) Push release Anchore CLI Docker image to Docker Hub
	@$(CI_CMD) push-prod-image-release "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"

push-rebuild: anchore-ci ## (Not available outside of CI) Rebuild and push prod Anchore CLI docker image to Docker Hub
	@$(CI_CMD) push-prod-image-rebuild "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"


# Helper targets
####################
cluster-up: anchore-ci venv ## Stand up/start kind cluster
	@$(CI_CMD) install-cluster-deps "$(VENV)"
	@$(ACTIVATE_VENV) && $(CI_CMD) cluster-up "$(CLUSTER_NAME)" "$(CLUSTER_CONFIG)" "$(K8S_VERSION)"

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

printvars: ## Print make variables
	@$(foreach V,$(sort $(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $V)),$(warning $V=$($V) ($(value $V)))))

help:
	@printf "\n%s\n\n" "usage: make <target>"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'
