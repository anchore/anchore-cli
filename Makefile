# Makefile for the Anchore CLI, a simple command line interface to the
# Anchore Engine service. The rules, directives, and variables in this
# Makefile enable testing, Docker image generation, and pushing Docker
# images.

# Docker Hub repos
DEV_IMAGE_REPO := robertprince/anchore-cli-dev
PROD_IMAGE_REPO := robertprince/anchore-cli

# Environment variables; set by/in CircleCI environment
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

# Make environment configuration
SHELL := /usr/bin/env bash
VENV := venv
ACTIVATE_VENV := source $(VENV)/bin/activate
PYTHON := $(VENV)/bin/python3

# Running make will invoke the help target
.DEFAULT_GOAL := help

# Run make serially. Note that recursively invoked make will still
# run recipes in parallel (unless they also contain .NOTPARALLEL)
.NOTPARALLEL:

# Setup a mock CI environment for running Make commands in the same environment as CircleCI
CI_RUNNER_IMAGE := docker.io/anchore/test-infra:python36
DOCKER_RUN_CMD = docker run -it --rm --network host -e WORKING_DIRECTORY=/home/circleci/project -e CI=false -e VERBOSE=$(VERBOSE) --entrypoint /anchore-ci/run_make_command.sh -v $(PWD):/home/circleci/project -v /var/run/docker.sock:/var/run/docker.sock $(CI_RUNNER_IMAGE)

# If running in CI, make is invoked from the test-infra container, so run commands directly
ifeq ($(CI), true)
  RUN_CMD := /anchore-ci/run_make_command.sh
  DOCKER_RUN_CMD := /anchore-ci/run_make_command.sh
else
  RUN_CMD = $(SHELL)
endif

# Define available make commands -- use ## on target names to create 'help' text

.PHONY: ci ## run full ci pipeline locally
ci: VERBOSE := true
ci: lint build test push

.PHONY: build
build: Dockerfile ## Build dev Anchore CLI Docker image
	@$(RUN_CMD) scripts/ci/build $(COMMIT_SHA) $(GIT_REPO) $(TEST_IMAGE_NAME)

.PHONY: push push-dev
push: push-dev ## Push dev Anchore CLI Docker image to Docker Hub
push-dev:
	@$(RUN_TASK) push_dev_image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

.PHONY: push-rc
push-rc:
	@$(RUN_TASK) push_rc_image "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

.PHONY: push-prod
push-prod:
	@$(RUN_TASK) push_prod_image_release "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"

.PHONY: push-rebuild
push-rebuild:
	@$(RUN_TASK) push_prod_image_rebuild "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

.PHONY: venv
venv: $(VENV)/bin/activate ## Set up a virtual environment
$(VENV)/bin/activate:
	python3 -m venv $(VENV)

.PHONY: install
install: venv setup.py requirements.txt ## Install to virtual environment
	@$(ACTIVATE_VENV) && $(PYTHON) setup.py install

.PHONY: install-dev
install-dev: venv setup.py requirements.txt ## Install to virtual environment in editable mode
	@$(ACTIVATE_VENV) && $(PYTHON) setup.py install --editable

.PHONY: lint
lint: venv ## Lint code (currently using flake8)
	@$(ACTIVATE_VENV) && $(RUN_CMD) scripts/ci/lint $(PYTHON)

# Note that the kind cluster will be run on the $CI_RUNNER_IMAGE that gets specified above
.PHONY: cluster-up
cluster-up: CLUSTER_CONFIG := tests/e2e/kind-config.yaml ## Bring up a kind (Kubernetes IN Docker) cluster to use for testing 
cluster-up: KUBERNETES_VERSION := 1.15.7
cluster-up: tests/e2e/kind-config.yaml
	$(DOCKER_RUN_CMD) kind_cluster_up $(CLUSTER_NAME) $(CLUSTER_CONFIG) $(KUBERNETES_VERSION)

.PHONY: cluster-down
cluster-down: ## Tear down/shut down the kind cluster
	$(DOCKER_RUN_CMD) kind_cluster_down $(CLUSTER_NAME)

.PHONY: test
test: test-unit test-functional test-e2e ## Run all tests: unit, functional, and e2e

.PHONY: test-unit
test-unit: venv ## Run unit tests (tox)
	@$(ACTIVATE_VENV) && $(RUN_CMD) scripts/ci/unit-tests $(PYTHON)

.PHONY: test-functional
test-functional: venv ## Run functional tests (tox)
	@$(ACTIVATE_VENV) && $(RUN_CMD) scripts/ci/functional-tests $(PYTHON)

.PHONY: test-e2e
test-e2e: cluster-up ## Set up, run end to end tests, then tear down the cluster
	$(DOCKER_RUN_CMD) setup_e2e_tests $(CLUSTER_NAME) $(COMMIT_SHA) $(DEV_IMAGE_REPO) $(GIT_BRANCH) $(GIT_REPO) $(GIT_TAG) $(TEST_IMAGE_NAME)
	@$(MAKE) run-test-e2e
	@$(MAKE) cluster-down

.PHONY: run-test-e2e
run-test-e2e: venv ## Run end to end tests
	$(ACTIVATE_VENV) && $(DOCKER_RUN_CMD) scripts/ci/e2e-tests.sh

.PHONY: clean
clean: ## Clean up the project directory; delete dev image
	@$(RUN_TASK) clean_project_dir "$(TEST_IMAGE_NAME)" "$(VENV)"

.PHONY: printvars
printvars: ## Print make variables
	@$(foreach V,$(sort $(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $V)),$(warning $V=$($V) ($(value $V)))))

#.PHONY: help
#help:
#	@$(RUN_TASK) help
#	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: help
help: ## Show this usage message
	@printf "\n%s\n\n" "usage: make <target>"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'
