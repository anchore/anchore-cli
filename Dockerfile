FROM python:2-alpine

ARG commit

LABEL "Maintainer"="dev@anchore.com"
LABEL "Commit"=${commit}
LABEL "Source"="https://github.com/anchore/anchore-cli"

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
