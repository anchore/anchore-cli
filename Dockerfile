FROM registry.access.redhat.com/ubi7/ubi:7.7-99 as anchore-cli-builder

######## This is stage1 where anchore wheels, binary deps, and any items from the source tree get staged to /build_output ########

ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

COPY . /buildsource
WORKDIR /buildsource

RUN set -ex && \
    mkdir -p /build_output /build_output/deps /build_output/configs /build_output/wheels

RUN set -ex && \
    echo "installing OS dependencies" && \
    yum update -y && \
    yum install -y gcc make rh-python36 rh-python36-python-wheel rh-python36-python-pip

# create anchore binaries
RUN set -ex && \
    echo "installing anchore" && \
    source /opt/rh/rh-python36/enable && \
    pip3 wheel --wheel-dir=/build_output/wheels . && \
    cp ./LICENSE /build_output/ && \
    cp ./docker-entrypoint.sh /build_output/configs/docker-entrypoint.sh 

RUN tar -z -c -v -C /build_output -f /anchore-buildblob.tgz .

FROM registry.access.redhat.com/ubi7/ubi:7.7-99 as anchore-cli-final

ARG CLI_COMMIT
ARG ANCHORE_CLI_VERSION="0.5.0"
ARG ANCHORE_CLI_RELEASE="r0"

# Copy artifacts from build step
COPY --from=anchore-cli-builder /build_output /build_output

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

# Setup container default configs and directories

WORKDIR /anchore-cli

# Perform OS setup

RUN set -ex && \
    groupadd --gid 1000 anchore && \
    useradd --uid 1000 --gid anchore --shell /bin/bash --create-home anchore && \
    mkdir -p /licenses/ && \
    cp /build_output/LICENSE /licenses/ && \
    cp /build_output/configs/docker-entrypoint.sh /docker-entrypoint.sh 
   
# Perform any base OS specific setup

# Setup python3 environment & create anchore-cli wrapper script for UBI7 
RUN echo -e '#!/usr/bin/env bash\n\nsource /opt/rh/rh-python36/enable' > /etc/profile.d/python3.sh && \
    echo -e '#!/usr/bin/env bash\n\n/docker-entrypoint.sh anchore-cli $@' > /usr/local/bin/anchore-cli && \
    chmod +x /usr/local/bin/anchore-cli

# Perform the anchore-cli build and install

RUN set -ex && \
    source /opt/rh/rh-python36/enable && \
    pip3 install --no-index --find-links=./ /build_output/wheels/*.whl && \
    rm -rf /build_output /root/.cache

USER anchore:anchore

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/bin/bash"]
