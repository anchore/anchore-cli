import json
import pytest

class TestDockerfile:

    @pytest.fixture(scope='class')
    def stdout(self, class_admin_call):
        out, err, code = class_admin_call(
            ['image', 'content', 'alfredodeza/vulnerable', 'dockerfile']
        )
        return out

    @pytest.mark.skip(reason="TODO: Fails on empty list")
    def test_dockerfile(self, stdout):
        # XXX this fails when uncommenting the exception eater in cli/utils.py
        # XXX investigate why dockerfile is an empty list
        # WARNING: failed to format output (returning raw output) - exception: argument should be a bytes-like object or ASCII string, not 'list'
        # {
        #     "content": [],
        #     "content_type": "dockerfile",
        #     "imageDigest": "sha256:0c03ccebef8d908f181a9fbd11eaf84c858be8396c71c89bf1b372ee59852eca"
        # }
        assert ''.join(stdout) == ''

class TestManifest:

    @pytest.fixture(scope='class')
    def stdout(self, class_admin_call):
        out, err, code = class_admin_call(
            ['image', 'content', 'alfredodeza/vulnerable', 'manifest']
        )
        try:
            return json.loads(out)
        except ValueError:
            raise ValueError('Unable to parse invalid JSON: %s' % str(out))

    def test_config(self, stdout):
        assert stdout['config']['digest']  == 'sha256:ab34be85ba4deaf0ba4770c6e4e61eaf56e4415a219867988dba2a0763f82503'
        assert stdout['config']['mediaType']  == 'application/vnd.docker.container.image.v1+json'
        assert stdout['config']['size']  == 2755

    def test_layers(self, stdout):
        # this is somewhat lazy, could look into each layer and digest
        # mediaType, and size
        assert len(stdout['layers']) == 2

    def test_mediaType(self, stdout):
        assert stdout['mediaType'] == 'application/vnd.docker.distribution.manifest.v2+json'

    def test_schemaVersion(self, stdout):
        assert stdout['schemaVersion'] == 2
