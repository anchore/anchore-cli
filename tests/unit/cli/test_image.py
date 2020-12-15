import pytest
from anchorecli.cli import image
from click.testing import CliRunner


@pytest.fixture
def response(monkeypatch):
    error = {
        "success": False,
        "payload": {},
        "error": {
            "detail": {"error_codes": []},
            "httpcode": 404,
            "message": "image is not analyzed - analysis_status: analyzing",
        },
        "httpcode": 404,
    }
    ok = {
        "success": True,
        "httpcode": 200,
        "payload": {
            "imageDigest": "sha256:0c03ccebef8d908f181a9fbd11eaf84c858be8396c71c89bf1b372ee59852eca",
            "vulnerabilities": [
                {
                    "advisory_data": {"cves": ["CVE-2018-19801"]},
                    "feed": "vulnerabilities",
                    "feed_group": "github:python",
                    "fix": "0.4.9",
                    "nvd_data": [],
                    "package": "aubio-0.4.8",
                    "package_cpe": "None",
                    "package_cpe23": "None",
                    "package_name": "aubio",
                    "package_path": "/usr/local/lib64/python3.6/site-packages/aubio",
                    "package_type": "python",
                    "package_version": "0.4.8",
                    "severity": "High",
                    "url": "https://github.com/advisories/GHSA-7vvr-h4p5-m7fh",
                    "vendor_data": [],
                    "vuln": "GHSA-7vvr-h4p5-m7fh",
                }
            ],
            "vulnerability_type": "all",
        },
        "error": {},
    }

    def apply(success=True, httpcode=200, has_error=None):
        if success:
            patch = lambda *a, **kw: ok
        else:
            if has_error:
                error["error"] = has_error
            patch = lambda *a, **kw: error

        monkeypatch.setattr(image.anchorecli.clients.apiexternal, "query_image", patch)

    return apply


headers = [
    "Vulnerability ID",
    "Package",
    "Severity",
    "Fix",
    "CVE Refs",
    "Vulnerability URL",
    "Type",
    "Feed Group",
    "Package Path",
]

vulnerability = [
    "GHSA-7vvr-h4p5-m7fh",
    "aubio-0.4.8",
    "High",
    "0.4.9",
    "https://github.com/advisories/GHSA-7vvr-h4p5-m7fh",
    "python",
    "github:python",
    "/usr/local/lib64/python3.6/site-packages/aubio",
]


class TestQueryVuln:
    def test_is_analyzing(self, monkeypatch, response):
        monkeypatch.setattr(
            image.anchorecli.cli.utils,
            "discover_inputimage",
            lambda *a, **kw: (None, None, "<digest>"),
        )
        monkeypatch.setattr(image, "config", {"jsonmode": False})
        runner = CliRunner()
        response(success=False)
        result = runner.invoke(image.query_vuln, ["centos/centos:8", "all"])
        assert result.exit_code == 100

    def test_not_yet_analyzed(self, monkeypatch, response):
        monkeypatch.setattr(
            image.anchorecli.cli.utils,
            "discover_inputimage",
            lambda *a, **kw: (None, None, "<digest>"),
        )
        monkeypatch.setattr(image, "config", {"jsonmode": False})
        runner = CliRunner()
        response(
            success=False,
            has_error={
                "detail": {"error_codes": []},
                "httpcode": 404,
                "message": "image is not analyzed - analysis_status: not_analyzed",
            },
        )
        result = runner.invoke(image.query_vuln, ["centos/centos:8", "all"])
        assert result.exit_code == 101

    @pytest.mark.parametrize("item", headers)
    def test_success_headers(self, monkeypatch, response, item):
        monkeypatch.setattr(
            image.anchorecli.cli.utils,
            "discover_inputimage",
            lambda *a, **kw: (None, None, "<digest>"),
        )
        monkeypatch.setattr(image, "config", {"jsonmode": False})
        runner = CliRunner()
        response(success=True)
        result = runner.invoke(image.query_vuln, ["centos/centos:8", "all"])
        assert result.exit_code == 0
        assert item in result.stdout

    @pytest.mark.parametrize("item", vulnerability)
    def test_success_info(self, monkeypatch, response, item):
        monkeypatch.setattr(
            image.anchorecli.cli.utils,
            "discover_inputimage",
            lambda *a, **kw: (None, None, "<digest>"),
        )
        monkeypatch.setattr(image, "config", {"jsonmode": False})
        runner = CliRunner()
        response(success=True)
        result = runner.invoke(image.query_vuln, ["centos/centos:8", "all"])
        assert result.exit_code == 0
        assert item in result.stdout


class TestDeleteImage:
    def test_deleted_pre_v080(self, monkeypatch, response):
        monkeypatch.setattr(
            image.anchorecli.cli.utils,
            "discover_inputimage",
            lambda *a, **kw: (None, None, "<digest>"),
        )
        monkeypatch.setattr(image, "config", {"jsonmode": False})
        monkeypatch.setattr(
            image.anchorecli.clients.apiexternal,
            "delete_image",
            lambda *a, **kw: {
                "success": True,
                "httpcode": 200,
                "payload": True,
                "error": {},
            },
        )
        runner = CliRunner()
        response(success=True)
        result = runner.invoke(image.delete, ["centos/centos:8"])
        assert result.exit_code == 0

    def test_delete_failed_pre_v080(self, monkeypatch, response):
        monkeypatch.setattr(
            image.anchorecli.cli.utils,
            "discover_inputimage",
            lambda *a, **kw: (None, None, "<digest>"),
        )
        monkeypatch.setattr(image, "config", {"jsonmode": False})
        monkeypatch.setattr(
            image.anchorecli.clients.apiexternal,
            "delete_image",
            lambda *a, **kw: {
                "success": False,
                "httpcode": 409,
                "payload": {},
                "error": "cannot delete image",
            },
        )
        runner = CliRunner()
        response(success=True)
        result = runner.invoke(image.delete, ["centos/centos:8"])
        assert result.exit_code == 1

    def test_is_deleting(self, monkeypatch, response):
        monkeypatch.setattr(
            image.anchorecli.cli.utils,
            "discover_inputimage",
            lambda *a, **kw: (None, None, "<digest>"),
        )
        monkeypatch.setattr(image, "config", {"jsonmode": False})
        monkeypatch.setattr(
            image.anchorecli.clients.apiexternal,
            "delete_image",
            lambda *a, **kw: {
                "success": True,
                "httpcode": 200,
                "payload": {"detail": None, "digest": "<digest>", "status": "deleting"},
                "error": {},
            },
        )
        runner = CliRunner()
        response(success=True)
        result = runner.invoke(image.delete, ["centos/centos:8"])
        assert result.exit_code == 0

    def test_delete_failed(self, monkeypatch, response):
        monkeypatch.setattr(
            image.anchorecli.cli.utils,
            "discover_inputimage",
            lambda *a, **kw: (None, None, "<digest>"),
        )
        monkeypatch.setattr(image, "config", {"jsonmode": False})
        monkeypatch.setattr(
            image.anchorecli.clients.apiexternal,
            "delete_image",
            lambda *a, **kw: {
                "success": True,
                "httpcode": 200,
                "payload": {
                    "detail": "cannot delete image",
                    "digest": "<digest>",
                    "status": "delete_failed",
                },
                "error": {},
            },
        )
        runner = CliRunner()
        response(success=True)
        result = runner.invoke(image.delete, ["centos/centos:8"])
        assert result.exit_code == 1


class TestImageSubcommandHelp:
    @pytest.mark.parametrize(
        "subcommand, output_start",
        [
            (image.wait, "Usage: wait"),
            (image.add, "Usage: add"),
            (image.import_image, "Usage: import"),
            (image.get, "Usage: get"),
            (image.imagelist, "Usage: list"),
            (image.query_content, "Usage: content"),
            (image.query_metadata, "Usage: metadata"),
            (image.query_vuln, "Usage: vuln"),
            (image.delete, "Usage: del"),
        ]
    )
    def test_image_subcommand_help(self, subcommand, output_start):
        runner = CliRunner()
        result = runner.invoke(subcommand, ["--help"])
        assert result.exit_code == 0
        assert result.output.startswith(output_start)