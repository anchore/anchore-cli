import os
import pytest

skip_versions = [
    "anchore/inline-scan:v0.6.0",
    "anchore/inline-scan:v0.5.0",
    "anchore/inline-scan:v0.5.1",
]

skip_reason = "Github Advisories not available in this version of Anchore Engine"


class TestNonOsVulnerabilities:
    """
    Vulnerability output sample:

    GHSA-grmf-4fq6-2r79        aubio-0.4.8                 Critical        0.4.9         CVE-2018-19800        https://github.com/advisories/GHSA-grmf-4fq6-2r79        python        github:python        /usr/local/lib64/python3.6/site-packages/aubio
    GHSA-74xw-82v7-hmrm        python-dbusmock-0.15        High            0.15.1        CVE-2015-1326         https://github.com/advisories/GHSA-74xw-82v7-hmrm        python        github:python        /usr/local/lib/python3.6/site-packages/python-dbusmock
    GHSA-7vvr-h4p5-m7fh        aubio-0.4.8                 High            0.4.9         CVE-2018-19801        https://github.com/advisories/GHSA-7vvr-h4p5-m7fh        python        github:python        /usr/local/lib64/python3.6/site-packages/aubio
    GHSA-c6jq-h4jp-72pr        aubio-0.4.8                 High            0.4.9         CVE-2018-19802        https://github.com/advisories/GHSA-c6jq-h4jp-72pr        python        github:python        /usr/local/lib64/python3.6/site-packages/aubio
    """

    @pytest.fixture(scope="class")
    def stdout(self, class_admin_call):
        """
        Fetch the output of non-os vulnerabilities in user-friendly format,
        split on newlines. This fixture is used once for the whole class
        """
        out, err, code = class_admin_call(
            ["image", "vuln", "alfredodeza/vulnerable", "non-os"]
        )
        return out.split("\n")

    def item_count(self, item, lines):
        return len([i for i in lines if item in i])

    def test_plain_output(self, stdout):
        assert len(stdout) == 6

    def test_severity(self, stdout):
        assert self.item_count(" Critical ", stdout) == 1
        assert self.item_count(" High ", stdout) == 3

    @pytest.mark.skipif(
        os.environ["PYTEST_CONTAINER"] in skip_versions, reason=skip_reason
    )
    def test_github_com(self, stdout):
        assert self.item_count("https://github.com/", stdout) == 4

    @pytest.mark.skipif(
        os.environ["PYTEST_CONTAINER"] in skip_versions, reason=skip_reason
    )
    def test_vulnerability_ids(self, stdout):
        output = "".join(stdout)
        assert " GHSA-grmf-4fq6-2r79" in output
        assert " GHSA-74xw-82v7-hmrm" in output
        assert " GHSA-7vvr-h4p5-m7fh" in output
        assert " GHSA-c6jq-h4jp-72pr" in output

    @pytest.mark.skipif(
        os.environ["PYTEST_CONTAINER"] in skip_versions, reason=skip_reason
    )
    def test_feed_group(self, stdout):
        assert self.item_count("github:python", stdout) == 4

    def test_type(self, stdout):
        assert self.item_count(" python ", stdout) == 4

    def test_packages(self, stdout):
        output = "".join(stdout)
        assert self.item_count(" aubio-0.4.8 ", stdout) == 3
        assert "python-dbusmock-0.15" in output

    @pytest.mark.skipif(
        os.environ["PYTEST_CONTAINER"] in skip_versions, reason=skip_reason
    )
    def test_fixes(self, stdout):
        output = "".join(stdout)
        assert self.item_count(" 0.4.9 ", stdout) == 3
        assert "0.15.1" in output

    def test_cve_refs(self, stdout):
        output = "".join(stdout)
        assert " CVE-2018-19800" in output
        assert " CVE-2015-1326 " in output
        assert " CVE-2018-19801" in output
        assert " CVE-2018-19802" in output

    def test_package_paths(self, stdout):
        output = "".join(stdout)
        assert "/usr/local/lib64/python3.6/site-packages/aubio         " in output
        assert "/usr/local/lib/python3.6/site-packages/python-dbusmock " in output
        assert "/usr/local/lib64/python3.6/site-packages/aubio         " in output
        assert "/usr/local/lib64/python3.6/site-packages/aubio         " in output
