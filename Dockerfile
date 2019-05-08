FROM registry.access.redhat.com/ubi7/ubi

ARG CLI_COMMIT
ARG ANCHORE_CLI_VERSION="0.4.0"
ARG ANCHORE_CLI_RELEASE="r0"

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
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Build dependencies

RUN yum update -y && \
    yum install -y rh-python36 rh-python36-python-wheel rh-python36-python-pip

COPY . /anchore-cli

WORKDIR /anchore-cli

# Perform OS setup

RUN cp docker-entrypoint.sh /docker-entrypoint.sh && \
    set -ex && \
    groupadd --gid 1000 anchore && \
    useradd --uid 1000 --gid anchore --shell /bin/bash --create-home anchore

# Perform any base OS specific setup

# Setup python3 environment & create anchore-cli wrapper script for UBI7 
RUN echo -e '#!/usr/bin/env bash\n\nsource /opt/rh/rh-python36/enable' > /etc/profile.d/python3.sh && \
    echo -e '#!/usr/bin/env bash\n\n/docker-entrypoint.sh anchore-cli $@' > /usr/local/bin/anchore-cli && \
    chmod +x /usr/local/bin/anchore-cli

# Perform the anchore-cli build and install

RUN source /opt/rh/rh-python36/enable && \
    pip3 install -r requirements.txt && \
    pip3 install . && \
    rm -rf /anchore-cli /root/.cache /wheels

USER anchore:anchore

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/bin/bash"]
