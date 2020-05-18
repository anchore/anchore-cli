###############################
# Makefile for the Anchore CLI, a simple command line interface to the
# Anchore Engine service. The rules, directives, and variables in this
# Makefile enable testing, Docker image generation, and pushing Docker
# images.
###############################


#### Docker Hub repos
###############################
DEV_IMAGE_REPO := robertprince/anchore-cli-dev
PROD_IMAGE_REPO := robertprince/anchore-cli


#### CircleCI environment variables
###############################
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
###############################
SHELL := /usr/bin/env bash
VENV := venv
ACTIVATE_VENV := source $(VENV)/bin/activate
PYTHON := $(VENV)/bin/python3
CI_USER := circleci
DOCKER_GID := $(shell ./scripts/ci/docker_gid_for_host_os)

# Running make will invoke the help target
.DEFAULT_GOAL := help

# Run make serially. Note that recursively invoked make will still
# run recipes in parallel (unless they also contain .NOTPARALLEL)
.NOTPARALLEL:

# Specify the Docker image to use in CI commands
# CI_RUNNER_IMAGE := docker.io/anchore/test-infra:python36
CI_RUNNER_IMAGE := test-infra:python36

# The Docker image invocation to be used when CI/build tasks are run
# locally; note that the GID of the group on the host that owns the
# Docker daemon's IPC socket should match in the host and container
# so that the container has access to the daemon.
DOCKER_RUN_CMD = docker run -it --rm --user $(CI_USER):$(DOCKER_GID) --network host -e WORKING_DIRECTORY=/home/circleci/project -e CI=false -e VERBOSE=$(VERBOSE) -e DOCKER_GROUP_ID=$(DOCKER_GID) --entrypoint /anchore-ci/run_make_command.sh -v $(PWD):/home/circleci/project -v /var/run/docker.sock:/var/run/docker.sock $(CI_RUNNER_IMAGE)

# If running in CI, make is invoked from the test-infra container, so run commands directly
ifeq ($(CI), true)
  RUN_CMD := /anchore-ci/run_make_command.sh
  DOCKER_RUN_CMD := /anchore-ci/run_make_command.sh
else
  RUN_CMD = $(SHELL)
endif


#### Make targets
###############################

.PHONY: ci ## run full ci pipeline locally
ci: VERBOSE := true
ci: lint build test push

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

.PHONY: build
build: Dockerfile ## Build dev Anchore CLI Docker image
	@$(RUN_CMD) scripts/ci/build $(COMMIT_SHA) $(GIT_REPO) $(TEST_IMAGE_NAME)

# Note that the kind cluster will be run on the $CI_RUNNER_IMAGE that gets specified above
.PHONY: cluster-up
cluster-up: CLUSTER_CONFIG := test/e2e/kind-config.yaml ## Bring up a kind (Kubernetes IN Docker) cluster to use for testing
cluster-up: KUBERNETES_VERSION := 1.15.7
cluster-up: test/e2e/kind-config.yaml
	$(DOCKER_RUN_CMD) kind_cluster_up $(CLUSTER_NAME) $(CLUSTER_CONFIG) $(KUBERNETES_VERSION)

.PHONY: cluster-down
cluster-down: ## Tear down/shut down the kind cluster
	$(DOCKER_RUN_CMD) kind_cluster_down $(CLUSTER_NAME)

.PHONY: test-unit
test-unit: venv ## Run unit tests (tox)
	@$(ACTIVATE_VENV) && $(RUN_CMD) scripts/ci/unit-tests $(PYTHON)

.PHONY: test-functional
test-functional: venv ## Run functional tests (tox)
	@$(ACTIVATE_VENV) && $(RUN_CMD) scripts/ci/functional-tests $(PYTHON)

.PHONY: test-e2e
test-e2e: cluster-up ## Set up and run end to end tests
	$(DOCKER_RUN_CMD) setup_e2e_tests $(CLUSTER_NAME) $(COMMIT_SHA) $(DEV_IMAGE_REPO) $(GIT_BRANCH) $(GIT_REPO) $(GIT_TAG) $(TEST_IMAGE_NAME)
	@$(MAKE) run-test-e2e
	@$(MAKE) cluster-down

.PHONY: run-test-e2e
run-test-e2e: venv ## Run end to end tests (set up done/cluster assumed to be running)
	$(ACTIVATE_VENV) && $(DOCKER_RUN_CMD) scripts/ci/e2e-tests $(PYTHON)

.PHONY: test
test: test-unit test-functional test-e2e ## Run all tests: unit, functional, and e2e

.PHONY: push push-dev
push: push-dev ## Push dev Anchore CLI Docker image to Docker Hub
push-dev:
	@$(RUN_CMD) scripts/ci/push-dev "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

.PHONY: push-rc
push-rc: ## Push RC Anchore CLI Docker image to Docker Hub (not available outside of CI)
	@$(RUN_CMD) scripts/ci/push_rc "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

.PHONY: push-prod
push-prod: ## Push release Anchore CLI Docker image to Docker Hub (not available outside of CI)
	@$(RUN_CMD) push_prod_image_release "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"

.PHONY: push-rebuild
push-rebuild: ## Rebuild and push prod Anchore CLI docker image to DOcker Hub (not available outside of CI)
	@$(RUN_CMD) push_prod_image_rebuild "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

.PHONY: dist-deb
dist-deb: ## Package Anchore CLI for Debian-based distros
	@$(RUN_CMD) scripts/make-dpkg.sh

.PHONY: dist-mac
dist-mac: ## Package Anchore CLI for MacOS
	@$(RUN_CMD) scripts/make-macos-bin.sh

.PHONY: dist-rpm
dist-rpm: ## Package Anchore CLI for RH-based distros
	@$(RUN_CMD) scripts/make-rpm.sh

.PHONY: clean
clean: ## Clean up the project directory and delete dev image
	@$(RUN_CMD) scripts/ci/clean $(TEST_IMAGE_NAME)

.PHONY: printvars
printvars: ## Print make variables
	@$(foreach V,$(sort $(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $V)),$(warning $V=$($V) ($(value $V)))))

.PHONY: help
help: ## Show this usage message
	@printf "\n%s\n\n" "usage: make <target>"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'
