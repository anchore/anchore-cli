FROM python:2-alpine

ARG CLI_COMMIT
ARG ANCHORE_CLI_VERSION="0.4.0"
ARG ANCHORE_CLI_RELEASE="dev"

# Container metadata section

MAINTAINER dev@anchore.com

LABEL anchore_cli_commit=$CLI_COMMIT \
      source="https://github.com/anchore/anchore-cli" \
      name="anchore-cli" \
      maintainer="dev@anchore.com" \
      vendor="Anchore Inc." \
      version=$ANCHORE_CLI_VERSION \
      release=$ANCHORE_CLI_RELEASE \
      summary="Anchore Engine CLI - python client for use against the anchore-engine container image scanning service, for policy-based security, best-practice and compliance enforcement." \
      description="Anchore is an open platform for container security and compliance that allows developers, operations, and security teams to discover, analyze, and certify container images on-premises or in the cloud. The Anchore CLI is a python client that can be used to access and manager Anchore Engine - the on-prem, OSS, API accessible service that allows ops and developers to perform detailed analysis, run queries, produce reports and define policies on container images that can be used in CI/CD pipelines to ensure that only containers that meet your organization’s requirements are deployed into production."

# Default values that should be overridden in most cases on each container exec
ENV ANCHORE_CLI_USER=admin
ENV ANCHORE_CLI_PASS=foobar
ENV ANCHORE_CLI_URL=http://localhost:8228/v1/
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN mkdir /app
COPY . /app
RUN pip install /app

CMD ["/bin/sh"]
