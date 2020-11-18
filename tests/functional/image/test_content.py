import json
import pytest


class TestDockerfile:
    @pytest.fixture(scope="class")
    def stdout(self, class_admin_call):
        out, err, code = class_admin_call(
            ["image", "content", "alfredodeza/vulnerable", "dockerfile"]
        )
        return "".join(out)

    def test_no_dockerfile(self, stdout):
        msg = "Error: There is no image content (dockerfile) to provide for alfredodeza/vulnerable\n\n"
        assert stdout == msg


class TestManifest:
    @pytest.fixture(scope="class")
    def stdout(self, class_admin_call):
        out, err, code = class_admin_call(
            ["image", "content", "alfredodeza/vulnerable", "manifest"]
        )
        if not out:
            return {}
        try:
            return json.loads(out)
        except ValueError:
            raise ValueError("Unable to parse invalid JSON: %s" % str(out))

    def test_config(self, stdout):
        assert (
            stdout["config"]["digest"]
            == "sha256:ab34be85ba4deaf0ba4770c6e4e61eaf56e4415a219867988dba2a0763f82503"
        )
        assert (
            stdout["config"]["mediaType"]
            == "application/vnd.docker.container.image.v1+json"
        )
        assert stdout["config"]["size"] == 2755

    def test_layers(self, stdout):
        # this is somewhat lazy, could look into each layer and digest
        # mediaType, and size
        assert len(stdout["layers"]) == 2

    def test_mediaType(self, stdout):
        assert (
            stdout["mediaType"]
            == "application/vnd.docker.distribution.manifest.v2+json"
        )

    def test_schemaVersion(self, stdout):
        assert stdout["schemaVersion"] == 2


class TestDockerHistory:
    @pytest.fixture(scope="class")
    def stdout(self, class_admin_call):
        out, err, code = class_admin_call(
            ["image", "content", "alfredodeza/vulnerable", "docker_history"]
        )
        if not out:
            return {}
        try:
            return json.loads(out)
        except ValueError:
            raise ValueError("Unable to parse invalid JSON: %s" % str(out))

    def test_history_length(self, stdout):
        assert len(stdout) == 4

    def test_comments(self, stdout):
        # This is prety ugly, but can't parametrize fixtures :(
        assert stdout[0]["Comment"] == ""
        assert stdout[1]["Comment"] == ""
        assert stdout[2]["Comment"] == ""
        assert stdout[3]["Comment"] == ""

    def test_created_by_0(self, stdout):
        created_by = stdout[0]["CreatedBy"]
        assert created_by == (
            "/bin/sh -c #(nop) ADD "
            "file:aa54047c80ba30064fe59adf4c978a929f38480be77af9ac644074bd5288ef18 "
            "in / "
        )

    def test_created_by_1(self, stdout):
        created_by = stdout[1]["CreatedBy"]
        assert created_by == (
            "/bin/sh -c #(nop)  LABEL org.label-schema.schema-version=1.0 "
            "org.label-schema.name=CentOS Base Image "
            "org.label-schema.vendor=CentOS org.label-schema.license=GPLv2 "
            "org.label-schema.build-date=20200114 "
            "org.opencontainers.image.title=CentOS Base Image "
            "org.opencontainers.image.vendor=CentOS "
            "org.opencontainers.image.licenses=GPL-2.0-only "
            "org.opencontainers.image.created=2020-01-14 00:00:00-08:00"
        )

    def test_created_by_2(self, stdout):
        created_by = stdout[2]["CreatedBy"]
        assert created_by == '/bin/sh -c #(nop)  CMD ["/bin/bash"]'

    def test_created_by_3(self, stdout):
        created_by = stdout[3]["CreatedBy"]
        assert created_by == "/bin/bash"

    # TODO: add all the other keys, sample output:
    # {'Comment': '',
    #  'Created': '2020-01-15T01:19:50.271835016Z',
    #  'CreatedBy': '/bin/sh -c #(nop) ADD '
    #               'file:aa54047c80ba30064fe59adf4c978a929f38480be77af9ac644074bd5288ef18 '
    #               'in / ',
    #  'Id': 'sha256:8a29a15cefaeccf6545f7ecf11298f9672d2f0cdaf9e357a95133ac3ad3e1f07',
    #  'Size': 73228446,
    #  'Tags': []},
