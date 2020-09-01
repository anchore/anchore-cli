import pytest
from anchorecli.cli import utils
import prettytable

class TestFormatErrorOutput:

    def setup(self):
        self.config = {'jsonmode': False}

    def test_fails_on_invalid_json(self):
        payload = Exception('could not access anchore service (user=None url=http://localhost:8228/v1)')
        result = utils.format_error_output(self.config, "policy", {}, payload)
        assert result == "Error: could not access anchore service (user=None url=http://localhost:8228/v1)\n"

    def test_empty_json_fallsback(self):
        result = utils.format_error_output(self.config, "policy", {}, "{}")
        assert result == '{}'

    def test_httpcode_is_included(self):
        result = utils.format_error_output(self.config, "policy", {}, '{"httpcode": 200}')
        assert result == 'HTTP Code: 200\n'

    def test_message_is_included(self):
        result = utils.format_error_output(self.config, "policy", {}, '{"message": "invalid input!"}')
        assert result == 'Error: invalid input!\n'

    def test_detail_is_included(self):
        result = utils.format_error_output(self.config, "policy", {}, '{"detail": "\'id\' is missing"}')
        assert result == "Detail: 'id' is missing\n"


class TestFormatErrorOutputJSONMode:

    def setup(self):
        self.config = {'jsonmode': True}

    def test_loads_valid_json(self):
        result = utils.format_error_output(self.config, "policy", {}, '{"message": "valid JSON"}')
        assert result == '{\n    "message": "valid JSON"\n}'

    def test_builds_valid_json_on_failure(self):
        result = utils.format_error_output(self.config, "policy", {}, 'invalid JSON!')
        assert result == '{\n    "message": "invalid JSON!"\n}'


class TestFormatErrorOutputAccountDelete:

    def setup(self):
        self.config = {'jsonmode': False}

    def test_invalid_account(self):
        result = utils.format_error_output(self.config, "account_delete", {}, '{"message": "Invalid account state change requested"}')
        assert 'Error: Invalid account state change requested' in result
        assert 'NOTE: accounts must be disabled (anchore-cli account disable <account>)' in result

    def test_state_change_is_valid(self):
        result = utils.format_error_output(self.config, "account_delete", {}, '{"message": "Unable to delete account"}')
        assert 'Error: Unable to delete account\n' == result


class TestCreateHint:

    def test_cannot_create_hint(self):
        result = utils.create_hint("should not create a hint here")
        assert result is None

    def test_creates_hint(self):
        result = utils.create_hint("'id' is a required property")
        assert 'Hint: The "id" key is not present in the JSON file' in result
        assert '"id": <value>' in result

    def test_cannot_create_hint_unquoted(self):
        result = utils.create_hint("unquoted_value is a required property")
        assert result is None

    @pytest.mark.parametrize('invalid_type', [None, [], {}, (), 1, True, False])
    def test_handles_non_strings(self, invalid_type):
        result = utils.create_hint(invalid_type)
        assert result is None


class TestFormatVulnerabilities:

    def test_no_query_type(self):
        payload = ['os', 'non-os', 'all']
        result = utils.format_vulnerabilities(payload, {})
        lines = result.split('\n')
        assert lines[0] == 'os: available'
        assert lines[1] == 'non-os: available'
        assert lines[2] == 'all: available'

    def test_os_nonos_all_header(self, payload):
        result = utils.format_vulnerabilities(payload, {'query_type': 'all'})
        header = result.split('\n')[0].split()
        assert header == [
            'Vulnerability', 'ID', 'Package', 'Severity', 'Fix', 'CVE',  'Refs',
            'Vulnerability',  'URL', 'Type', 'Feed', 'Group', 'Package', 'Path'
        ]

    def test_all(self, payload):
        result = utils.format_vulnerabilities(payload, {'query_type': 'all'})
        line = result.split('\n')[1].split()
        assert line == [
            'RHSA-2019:4190',
            'nss-3.44.0-4.el7',
            'High',
            '0:3.44.0-7.el7_7',
            'CVE-2019-11729,CVE-2019-11745',
            'https://access.redhat.com/errata/RHSA-2019:4190',
            'rpm',
            'centos:7',
            'None',
        ]

    def test_vulnerability_id_missing(self, payload):
        result = utils.format_vulnerabilities(payload, {'query_type': 'all'})
        line = result.split('\n')[-1].split()
        assert line == [
            'RHSA-2019:4190',
            'nss-util-3.44.0-3.el7',
            'High',
            '0:3.44.0-4.el7_7',
            'CVE-2019-11745',
            'https://access.redhat.com/errata/RHSA-2019:4190',
            'rpm',
            'centos:7',
            'None',
        ]


class TestFormatContentQuery:

    def test_no_content(self):
        payload = {}
        result = utils.format_content_query(payload)
        assert result == ''

    @pytest.mark.parametrize('content', [[], '', None])
    def test_content_defined_but_empty(self, content):
        payload = {'content': content}
        result = utils.format_content_query(payload)
        assert result == ''

    def test_content_cannot_be_decoded(self):
        payload = {'content': b'\t23hsdf'}
        result = utils.format_content_query(payload)
        assert result == ''

    @pytest.mark.parametrize('content', [b'RlJPTSBjZW50b3M3', 'RlJPTSBjZW50b3M3'])
    def test_content_gets_decoded(self, content):
        payload = {'content': content}
        result = utils.format_content_query(payload)
        assert result == 'FROM centos7'


class TestFormatMetadataQuery:

    _manifest_metadata = 'eyJzY2hlbWFWZXJzaW9uIjogMiwgIm1lZGlhVHlwZSI6ICJhcHBsaWNhdGlvbi92bmQuZG9ja2Vy\nLmRpc3RyaWJ1dGlvbi5tYW5pZmVzdC52Mitqc29uIiwgImNvbmZpZyI6IHsibWVkaWFUeXBlIjog\nImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuY29udGFpbmVyLmltYWdlLnYxK2pzb24iLCAic2l6ZSI6\nIDczMTIsICJkaWdlc3QiOiAic2hhMjU2Ojk1OGQzNDkxYzA5YWU1MDAzNzUwMTFiZTNlZTc3YWVj\nMDIzODdlMTFiYTg1ZDQ4NmZlMzY1ZTY2N2JkNWUyOWEifSwgImxheWVycyI6IFt7Im1lZGlhVHlw\nZSI6ICJhcHBsaWNhdGlvbi92bmQuZG9ja2VyLmltYWdlLnJvb3Rmcy5kaWZmLnRhci5nemlwIiwg\nInNpemUiOiA1MDM5NjAwMCwgImRpZ2VzdCI6ICJzaGEyNTY6ZDZmZjM2YzllYzQ4MjJjOWZmODk1\nMzU2MGY3YmE0MTY1M2IzNDhhOWMxMTM2NzU1ZTY1MzU3NWY1OGZiZGVkNyJ9LCB7Im1lZGlhVHlw\nZSI6ICJhcHBsaWNhdGlvbi92bmQuZG9ja2VyLmltYWdlLnJvb3Rmcy5kaWZmLnRhci5nemlwIiwg\nInNpemUiOiA3ODExNTcwLCAiZGlnZXN0IjogInNoYTI1NjpjOTU4ZDY1YjMwOTBhZWZlYTkxMjg0\nZDAxOGIyYTg2NTMwYTNjODE3NGI3MjYxNmM0ZTc2OTkzYzY5NmE1Nzk3In0sIHsibWVkaWFUeXBl\nIjogImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuaW1hZ2Uucm9vdGZzLmRpZmYudGFyLmd6aXAiLCAi\nc2l6ZSI6IDk5OTYzMzcsICJkaWdlc3QiOiAic2hhMjU2OmVkYWYwYTZiMDkyZjU2NzNlYzA1YjQw\nZWRiNjA2Y2U1ODg4MWIyZjQwNDk0MjUxMTE3ZDMxODA1MjI1ZWYwNjQifSwgeyJtZWRpYVR5cGUi\nOiAiYXBwbGljYXRpb24vdm5kLmRvY2tlci5pbWFnZS5yb290ZnMuZGlmZi50YXIuZ3ppcCIsICJz\naXplIjogNTE4Mjk4MjYsICJkaWdlc3QiOiAic2hhMjU2OjgwOTMxY2Y2ODgxNjczZmQxNjFhM2Zk\nNzNlODk3MWZlNGE1NjlmZDdmYmI0NGU5NTZkMjYxY2E1OGQ5N2RmYWIifSwgeyJtZWRpYVR5cGUi\nOiAiYXBwbGljYXRpb24vdm5kLmRvY2tlci5pbWFnZS5yb290ZnMuZGlmZi50YXIuZ3ppcCIsICJz\naXplIjogMTkyMjQzNDk5LCAiZGlnZXN0IjogInNoYTI1NjpiYzFiOGFjYTM4MjVlNmMzYjU3ZTI4\nYzgwNzUxODBmOTc4NzkxNjFkZDU4MzMzZGUxM2Y2YjZkYTBmODQyYWYzIn0sIHsibWVkaWFUeXBl\nIjogImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuaW1hZ2Uucm9vdGZzLmRpZmYudGFyLmd6aXAiLCAi\nc2l6ZSI6IDE5OSwgImRpZ2VzdCI6ICJzaGEyNTY6ZTY0ZWRhZmUzZjM1OGZiNmYyMDlmMTQwYWYy\nNGQ5ODM2MjQ3MzYxNzM2MGQ2ZTUxNDFhMGVkZjY5N2E4MjNiYiJ9LCB7Im1lZGlhVHlwZSI6ICJh\ncHBsaWNhdGlvbi92bmQuZG9ja2VyLmltYWdlLnJvb3Rmcy5kaWZmLnRhci5nemlwIiwgInNpemUi\nOiAyMjg3ODEwNiwgImRpZ2VzdCI6ICJzaGEyNTY6NWY3ZTMxYTIyNWJjZDdjZmQ0YzI5MzVhZDc5\nNjQyOTk0NjU3MTJmMmYyMDU2NzlkMzc2NTQ4NGZkZDhjZjJlYiJ9LCB7Im1lZGlhVHlwZSI6ICJh\ncHBsaWNhdGlvbi92bmQuZG9ja2VyLmltYWdlLnJvb3Rmcy5kaWZmLnRhci5nemlwIiwgInNpemUi\nOiAxNDMsICJkaWdlc3QiOiAic2hhMjU2OmE3YTI1ODJlM2EyODFmZmJlY2Y3ZTcxMzgyZGVlNTA0\nNDNkZmM0NzUzNzU2NjgwZjM1YjViZTk5OTEwYzY0NDMifV19\n'
    _docker_history_metadata = 'W3siQ29tbWVudCI6ICIiLCAiQ3JlYXRlZCI6ICIyMDIwLTA4LTA0VDE1OjQyOjMzLjg1MDY0MzA1\nMloiLCAiQ3JlYXRlZEJ5IjogIi9iaW4vc2ggLWMgIyhub3ApIEFERCBmaWxlOjRiMDNiNWY1NTFl\nM2ZiZGY0N2VjNjA5NzEyMDA3MzI3ODI4Zjc1MzBjYzM0NTVjNDNiYmNkY2FmNDQ5YTc1YTkgaW4g\nLyAiLCAiSWQiOiAic2hhMjU2OmQ2ZmYzNmM5ZWM0ODIyYzlmZjg5NTM1NjBmN2JhNDE2NTNiMzQ4\nYTljMTEzNjc1NWU2NTM1NzVmNThmYmRlZDciLCAiU2l6ZSI6IDUwMzk2MDAwLCAiVGFncyI6IFtd\nfSwgeyJDb21tZW50IjogIiIsICJDcmVhdGVkIjogIjIwMjAtMDgtMDRUMTU6NDI6MzQuMTI4MzA0\nNjA2WiIsICJDcmVhdGVkQnkiOiAiL2Jpbi9zaCAtYyAjKG5vcCkgIENNRCBbXCJiYXNoXCJdIiwg\nIklkIjogIjxtaXNzaW5nPiIsICJTaXplIjogMCwgIlRhZ3MiOiBbXX0sIHsiQ29tbWVudCI6ICIi\nLCAiQ3JlYXRlZCI6ICIyMDIwLTA4LTA0VDIzOjI2OjI4LjY1MTE4MTg4NVoiLCAiQ3JlYXRlZEJ5\nIjogIi9iaW4vc2ggLWMgYXB0LWdldCB1cGRhdGUgJiYgYXB0LWdldCBpbnN0YWxsIC15IC0tbm8t\naW5zdGFsbC1yZWNvbW1lbmRzIFx0XHRjYS1jZXJ0aWZpY2F0ZXMgXHRcdGN1cmwgXHRcdG5ldGJh\nc2UgXHRcdHdnZXQgXHQmJiBybSAtcmYgL3Zhci9saWIvYXB0L2xpc3RzLyoiLCAiSWQiOiAic2hh\nMjU2OmM5NThkNjViMzA5MGFlZmVhOTEyODRkMDE4YjJhODY1MzBhM2M4MTc0YjcyNjE2YzRlNzY5\nOTNjNjk2YTU3OTciLCAiU2l6ZSI6IDc4MTE1NzAsICJUYWdzIjogW119LCB7IkNvbW1lbnQiOiAi\nIiwgIkNyZWF0ZWQiOiAiMjAyMC0wOC0wNFQyMzoyNjozNC42NTc1MjgyMVoiLCAiQ3JlYXRlZEJ5\nIjogIi9iaW4vc2ggLWMgc2V0IC1leDsgXHRpZiAhIGNvbW1hbmQgLXYgZ3BnID4gL2Rldi9udWxs\nOyB0aGVuIFx0XHRhcHQtZ2V0IHVwZGF0ZTsgXHRcdGFwdC1nZXQgaW5zdGFsbCAteSAtLW5vLWlu\nc3RhbGwtcmVjb21tZW5kcyBcdFx0XHRnbnVwZyBcdFx0XHRkaXJtbmdyIFx0XHQ7IFx0XHRybSAt\ncmYgL3Zhci9saWIvYXB0L2xpc3RzLyo7IFx0ZmkiLCAiSWQiOiAic2hhMjU2OmVkYWYwYTZiMDky\nZjU2NzNlYzA1YjQwZWRiNjA2Y2U1ODg4MWIyZjQwNDk0MjUxMTE3ZDMxODA1MjI1ZWYwNjQiLCAi\nU2l6ZSI6IDk5OTYzMzcsICJUYWdzIjogW119LCB7IkNvbW1lbnQiOiAiIiwgIkNyZWF0ZWQiOiAi\nMjAyMC0wOC0wNFQyMzoyNjo1NS4wOTg4MTU0ODRaIiwgIkNyZWF0ZWRCeSI6ICIvYmluL3NoIC1j\nIGFwdC1nZXQgdXBkYXRlICYmIGFwdC1nZXQgaW5zdGFsbCAteSAtLW5vLWluc3RhbGwtcmVjb21t\nZW5kcyBcdFx0Z2l0IFx0XHRtZXJjdXJpYWwgXHRcdG9wZW5zc2gtY2xpZW50IFx0XHRzdWJ2ZXJz\naW9uIFx0XHRcdFx0cHJvY3BzIFx0JiYgcm0gLXJmIC92YXIvbGliL2FwdC9saXN0cy8qIiwgIklk\nIjogInNoYTI1Njo4MDkzMWNmNjg4MTY3M2ZkMTYxYTNmZDczZTg5NzFmZTRhNTY5ZmQ3ZmJiNDRl\nOTU2ZDI2MWNhNThkOTdkZmFiIiwgIlNpemUiOiA1MTgyOTgyNiwgIlRhZ3MiOiBbXX0sIHsiQ29t\nbWVudCI6ICIiLCAiQ3JlYXRlZCI6ICIyMDIwLTA4LTA0VDIzOjI3OjQ2Ljk5ODUxMDI5MloiLCAi\nQ3JlYXRlZEJ5IjogIi9iaW4vc2ggLWMgc2V0IC1leDsgXHRhcHQtZ2V0IHVwZGF0ZTsgXHRERUJJ\nQU5fRlJPTlRFTkQ9bm9uaW50ZXJhY3RpdmUgXHRhcHQtZ2V0IGluc3RhbGwgLXkgLS1uby1pbnN0\nYWxsLXJlY29tbWVuZHMgXHRcdGF1dG9jb25mIFx0XHRhdXRvbWFrZSBcdFx0YnppcDIgXHRcdGRw\na2ctZGV2IFx0XHRmaWxlIFx0XHRnKysgXHRcdGdjYyBcdFx0aW1hZ2VtYWdpY2sgXHRcdGxpYmJ6\nMi1kZXYgXHRcdGxpYmM2LWRldiBcdFx0bGliY3VybDQtb3BlbnNzbC1kZXYgXHRcdGxpYmRiLWRl\ndiBcdFx0bGliZXZlbnQtZGV2IFx0XHRsaWJmZmktZGV2IFx0XHRsaWJnZGJtLWRldiBcdFx0bGli\nZ2xpYjIuMC1kZXYgXHRcdGxpYmdtcC1kZXYgXHRcdGxpYmpwZWctZGV2IFx0XHRsaWJrcmI1LWRl\ndiBcdFx0bGlibHptYS1kZXYgXHRcdGxpYm1hZ2lja2NvcmUtZGV2IFx0XHRsaWJtYWdpY2t3YW5k\nLWRldiBcdFx0bGlibWF4bWluZGRiLWRldiBcdFx0bGlibmN1cnNlczUtZGV2IFx0XHRsaWJuY3Vy\nc2VzdzUtZGV2IFx0XHRsaWJwbmctZGV2IFx0XHRsaWJwcS1kZXYgXHRcdGxpYnJlYWRsaW5lLWRl\ndiBcdFx0bGlic3FsaXRlMy1kZXYgXHRcdGxpYnNzbC1kZXYgXHRcdGxpYnRvb2wgXHRcdGxpYndl\nYnAtZGV2IFx0XHRsaWJ4bWwyLWRldiBcdFx0bGlieHNsdC1kZXYgXHRcdGxpYnlhbWwtZGV2IFx0\nXHRtYWtlIFx0XHRwYXRjaCBcdFx0dW56aXAgXHRcdHh6LXV0aWxzIFx0XHR6bGliMWctZGV2IFx0\nXHRcdFx0JCggXHRcdFx0aWYgYXB0LWNhY2hlIHNob3cgJ2RlZmF1bHQtbGlibXlzcWxjbGllbnQt\nZGV2JyAyPi9kZXYvbnVsbCB8IGdyZXAgLXEgJ15WZXJzaW9uOic7IHRoZW4gXHRcdFx0XHRlY2hv\nICdkZWZhdWx0LWxpYm15c3FsY2xpZW50LWRldic7IFx0XHRcdGVsc2UgXHRcdFx0XHRlY2hvICds\naWJteXNxbGNsaWVudC1kZXYnOyBcdFx0XHRmaSBcdFx0KSBcdDsgXHRybSAtcmYgL3Zhci9saWIv\nYXB0L2xpc3RzLyoiLCAiSWQiOiAic2hhMjU2OmJjMWI4YWNhMzgyNWU2YzNiNTdlMjhjODA3NTE4\nMGY5Nzg3OTE2MWRkNTgzMzNkZTEzZjZiNmRhMGY4NDJhZjMiLCAiU2l6ZSI6IDE5MjI0MzQ5OSwg\nIlRhZ3MiOiBbXX0sIHsiQ29tbWVudCI6ICIiLCAiQ3JlYXRlZCI6ICIyMDIwLTA4LTA1VDA3OjEz\nOjU4LjU5NTIwMjY0MloiLCAiQ3JlYXRlZEJ5IjogIi9iaW4vc2ggLWMgc2V0IC1ldXg7IFx0bWtk\naXIgLXAgL3Vzci9sb2NhbC9ldGM7IFx0eyBcdFx0ZWNobyAnaW5zdGFsbDogLS1uby1kb2N1bWVu\ndCc7IFx0XHRlY2hvICd1cGRhdGU6IC0tbm8tZG9jdW1lbnQnOyBcdH0gPj4gL3Vzci9sb2NhbC9l\ndGMvZ2VtcmMiLCAiSWQiOiAic2hhMjU2OmU2NGVkYWZlM2YzNThmYjZmMjA5ZjE0MGFmMjRkOTgz\nNjI0NzM2MTczNjBkNmU1MTQxYTBlZGY2OTdhODIzYmIiLCAiU2l6ZSI6IDE5OSwgIlRhZ3MiOiBb\nXX0sIHsiQ29tbWVudCI6ICIiLCAiQ3JlYXRlZCI6ICIyMDIwLTA4LTA1VDA3OjEzOjU4Ljc4MjQz\nODE4NVoiLCAiQ3JlYXRlZEJ5IjogIi9iaW4vc2ggLWMgIyhub3ApICBFTlYgTEFORz1DLlVURi04\nIiwgIklkIjogIjxtaXNzaW5nPiIsICJTaXplIjogMCwgIlRhZ3MiOiBbXX0sIHsiQ29tbWVudCI6\nICIiLCAiQ3JlYXRlZCI6ICIyMDIwLTA4LTA1VDA3OjEzOjU4Ljk2MjAyMzk4OFoiLCAiQ3JlYXRl\nZEJ5IjogIi9iaW4vc2ggLWMgIyhub3ApICBFTlYgUlVCWV9NQUpPUj0yLjciLCAiSWQiOiAiPG1p\nc3Npbmc+IiwgIlNpemUiOiAwLCAiVGFncyI6IFtdfSwgeyJDb21tZW50IjogIiIsICJDcmVhdGVk\nIjogIjIwMjAtMDgtMDVUMDc6MTM6NTkuMTMwOTMyOTk0WiIsICJDcmVhdGVkQnkiOiAiL2Jpbi9z\naCAtYyAjKG5vcCkgIEVOViBSVUJZX1ZFUlNJT049Mi43LjEiLCAiSWQiOiAiPG1pc3Npbmc+Iiwg\nIlNpemUiOiAwLCAiVGFncyI6IFtdfSwgeyJDb21tZW50IjogIiIsICJDcmVhdGVkIjogIjIwMjAt\nMDgtMDVUMDc6MTM6NTkuMzA2MTMxMDI5WiIsICJDcmVhdGVkQnkiOiAiL2Jpbi9zaCAtYyAjKG5v\ncCkgIEVOViBSVUJZX0RPV05MT0FEX1NIQTI1Nj1iMjI0Zjk4NDQ2NDZjYzkyNzY1ZGY4Mjg4YTQ2\nODM4NTExYzFjZWM1YjU1MGQ4ODc0YmQ0Njg2YTkwNGZjZWU3IiwgIklkIjogIjxtaXNzaW5nPiIs\nICJTaXplIjogMCwgIlRhZ3MiOiBbXX0sIHsiQ29tbWVudCI6ICIiLCAiQ3JlYXRlZCI6ICIyMDIw\nLTA4LTA1VDA3OjE2OjQ0Ljc5NjY5NDc5NloiLCAiQ3JlYXRlZEJ5IjogIi9iaW4vc2ggLWMgc2V0\nIC1ldXg7IFx0XHRzYXZlZEFwdE1hcms9XCIkKGFwdC1tYXJrIHNob3dtYW51YWwpXCI7IFx0YXB0\nLWdldCB1cGRhdGU7IFx0YXB0LWdldCBpbnN0YWxsIC15IC0tbm8taW5zdGFsbC1yZWNvbW1lbmRz\nIFx0XHRiaXNvbiBcdFx0ZHBrZy1kZXYgXHRcdGxpYmdkYm0tZGV2IFx0XHRydWJ5IFx0OyBcdHJt\nIC1yZiAvdmFyL2xpYi9hcHQvbGlzdHMvKjsgXHRcdHdnZXQgLU8gcnVieS50YXIueHogXCJodHRw\nczovL2NhY2hlLnJ1YnktbGFuZy5vcmcvcHViL3J1YnkvJHtSVUJZX01BSk9SJS1yY30vcnVieS0k\nUlVCWV9WRVJTSU9OLnRhci54elwiOyBcdGVjaG8gXCIkUlVCWV9ET1dOTE9BRF9TSEEyNTYgKnJ1\nYnkudGFyLnh6XCIgfCBzaGEyNTZzdW0gLS1jaGVjayAtLXN0cmljdDsgXHRcdG1rZGlyIC1wIC91\nc3Ivc3JjL3J1Ynk7IFx0dGFyIC14SmYgcnVieS50YXIueHogLUMgL3Vzci9zcmMvcnVieSAtLXN0\ncmlwLWNvbXBvbmVudHM9MTsgXHRybSBydWJ5LnRhci54ejsgXHRcdGNkIC91c3Ivc3JjL3J1Ynk7\nIFx0XHR7IFx0XHRlY2hvICcjZGVmaW5lIEVOQUJMRV9QQVRIX0NIRUNLIDAnOyBcdFx0ZWNobzsg\nXHRcdGNhdCBmaWxlLmM7IFx0fSA+IGZpbGUuYy5uZXc7IFx0bXYgZmlsZS5jLm5ldyBmaWxlLmM7\nIFx0XHRhdXRvY29uZjsgXHRnbnVBcmNoPVwiJChkcGtnLWFyY2hpdGVjdHVyZSAtLXF1ZXJ5IERF\nQl9CVUlMRF9HTlVfVFlQRSlcIjsgXHQuL2NvbmZpZ3VyZSBcdFx0LS1idWlsZD1cIiRnbnVBcmNo\nXCIgXHRcdC0tZGlzYWJsZS1pbnN0YWxsLWRvYyBcdFx0LS1lbmFibGUtc2hhcmVkIFx0OyBcdG1h\na2UgLWogXCIkKG5wcm9jKVwiOyBcdG1ha2UgaW5zdGFsbDsgXHRcdGFwdC1tYXJrIGF1dG8gJy4q\nJyA+IC9kZXYvbnVsbDsgXHRhcHQtbWFyayBtYW51YWwgJHNhdmVkQXB0TWFyayA+IC9kZXYvbnVs\nbDsgXHRmaW5kIC91c3IvbG9jYWwgLXR5cGUgZiAtZXhlY3V0YWJsZSAtbm90IFxcKCAtbmFtZSAn\nKnRraW50ZXIqJyBcXCkgLWV4ZWMgbGRkICd7fScgJzsnIFx0XHR8IGF3ayAnLz0+LyB7IHByaW50\nICQoTkYtMSkgfScgXHRcdHwgc29ydCAtdSBcdFx0fCB4YXJncyAtciBkcGtnLXF1ZXJ5IC0tc2Vh\ncmNoIFx0XHR8IGN1dCAtZDogLWYxIFx0XHR8IHNvcnQgLXUgXHRcdHwgeGFyZ3MgLXIgYXB0LW1h\ncmsgbWFudWFsIFx0OyBcdGFwdC1nZXQgcHVyZ2UgLXkgLS1hdXRvLXJlbW92ZSAtbyBBUFQ6OkF1\ndG9SZW1vdmU6OlJlY29tbWVuZHNJbXBvcnRhbnQ9ZmFsc2U7IFx0XHRjZCAvOyBcdHJtIC1yIC91\nc3Ivc3JjL3J1Ynk7IFx0ISBkcGtnIC1sIHwgZ3JlcCAtaSBydWJ5OyBcdFsgXCIkKGNvbW1hbmQg\nLXYgcnVieSlcIiA9ICcvdXNyL2xvY2FsL2Jpbi9ydWJ5JyBdOyBcdHJ1YnkgLS12ZXJzaW9uOyBc\ndGdlbSAtLXZlcnNpb247IFx0YnVuZGxlIC0tdmVyc2lvbiIsICJJZCI6ICJzaGEyNTY6NWY3ZTMx\nYTIyNWJjZDdjZmQ0YzI5MzVhZDc5NjQyOTk0NjU3MTJmMmYyMDU2NzlkMzc2NTQ4NGZkZDhjZjJl\nYiIsICJTaXplIjogMjI4NzgxMDYsICJUYWdzIjogW119LCB7IkNvbW1lbnQiOiAiIiwgIkNyZWF0\nZWQiOiAiMjAyMC0wOC0wNVQwNzoxNjo0NS4wMTMxNzU3ODFaIiwgIkNyZWF0ZWRCeSI6ICIvYmlu\nL3NoIC1jICMobm9wKSAgRU5WIEdFTV9IT01FPS91c3IvbG9jYWwvYnVuZGxlIiwgIklkIjogIjxt\naXNzaW5nPiIsICJTaXplIjogMCwgIlRhZ3MiOiBbXX0sIHsiQ29tbWVudCI6ICIiLCAiQ3JlYXRl\nZCI6ICIyMDIwLTA4LTA1VDA3OjE2OjQ1LjE4MjM4NTA3MloiLCAiQ3JlYXRlZEJ5IjogIi9iaW4v\nc2ggLWMgIyhub3ApICBFTlYgQlVORExFX1NJTEVOQ0VfUk9PVF9XQVJOSU5HPTEgQlVORExFX0FQ\nUF9DT05GSUc9L3Vzci9sb2NhbC9idW5kbGUiLCAiSWQiOiAiPG1pc3Npbmc+IiwgIlNpemUiOiAw\nLCAiVGFncyI6IFtdfSwgeyJDb21tZW50IjogIiIsICJDcmVhdGVkIjogIjIwMjAtMDgtMDVUMDc6\nMTY6NDUuMzczMTU2MzY2WiIsICJDcmVhdGVkQnkiOiAiL2Jpbi9zaCAtYyAjKG5vcCkgIEVOViBQ\nQVRIPS91c3IvbG9jYWwvYnVuZGxlL2JpbjovdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46\nL3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iLCAiSWQiOiAiPG1pc3Npbmc+IiwgIlNpemUi\nOiAwLCAiVGFncyI6IFtdfSwgeyJDb21tZW50IjogIiIsICJDcmVhdGVkIjogIjIwMjAtMDgtMDVU\nMDc6MTY6NDYuMTAyNTk5Mzg3WiIsICJDcmVhdGVkQnkiOiAiL2Jpbi9zaCAtYyBta2RpciAtcCBc\nIiRHRU1fSE9NRVwiICYmIGNobW9kIDc3NyBcIiRHRU1fSE9NRVwiIiwgIklkIjogInNoYTI1Njph\nN2EyNTgyZTNhMjgxZmZiZWNmN2U3MTM4MmRlZTUwNDQzZGZjNDc1Mzc1NjY4MGYzNWI1YmU5OTkx\nMGM2NDQzIiwgIlNpemUiOiAxNDMsICJUYWdzIjogW119LCB7IkNvbW1lbnQiOiAiIiwgIkNyZWF0\nZWQiOiAiMjAyMC0wOC0wNVQwNzoxNjo0Ni4yODY5NTc4ODFaIiwgIkNyZWF0ZWRCeSI6ICIvYmlu\nL3NoIC1jICMobm9wKSAgQ01EIFtcImlyYlwiXSIsICJJZCI6ICI8bWlzc2luZz4iLCAiU2l6ZSI6\nIDAsICJUYWdzIjogW119XQ==\n'

    def test_no_payload(self):
        payload = {}
        result = utils.format_metadata_query(payload)
        assert result == ''

    @pytest.mark.parametrize('payload', [{}, None])
    def test_payload_defined_but_empty(self, payload):
        result = utils.format_metadata_query(payload)
        assert result == ''

    @pytest.mark.parametrize('metadata', ['', None])
    def test_metadata_defined_but_empty(self, metadata):
        payload = {'metadata': metadata}
        result = utils.format_metadata_query(payload)
        assert result == ''

    def test_metadata_cannot_be_decoded(self):
        payload = {'metadata': b'\t23hsdf'}
        result = utils.format_metadata_query(payload)
        assert result == ''

    @pytest.mark.parametrize('metadata', [_manifest_metadata, _docker_history_metadata])
    def test_content_gets_decoded(self, metadata):
        payload = {'metadata': metadata}
        result = utils.format_metadata_query(payload)
        assert result.startswith('Metadata: ')

    @pytest.mark.parametrize('image_digest', ['', None])
    def test_image_digest_defined_but_empty(self, image_digest):
        payload = {'imageDigest': image_digest}
        result = utils.format_metadata_query(payload)
        assert result == ''

    def test_image_digest_parsed(self):
        image_digest = 'sha256:0c03ccebef8d908f181a9fbd11eaf84c858be8396c71c89bf1b372ee59852eca'
        payload = {'imageDigest': image_digest}
        result = utils.format_metadata_query(payload)
        assert result == 'Image Digest: {}\n'.format(image_digest)

    @pytest.mark.parametrize('mtype', ['', None])
    def test_metadata_type_defined_but_empty(self, mtype):
        payload = {'metadata_type': mtype}
        result = utils.format_metadata_query(payload)
        assert result == ''

    @pytest.mark.parametrize('mtype', ['dockerfile', 'docker_history', 'manifest'])
    def test_metadata_type_parsed(self, mtype):
        payload = {'metadata_type': mtype}
        result = utils.format_metadata_query(payload)
        assert result == 'Metadata Type: {}\n'.format(mtype)


class TestFormatContentMalware:

    @pytest.mark.parametrize('content, expected', [({
        "content": [
            {
                "enabled": True,
                "findings": [
                    {
                        "path": "/elf_payload1",
                        "signature": "Unix.Trojan.MSShellcode-40"
                    }
                ],
                "metadata": {
                    "db_version": {
                        "bytecode": "331",
                        "daily": "25890",
                        "main": "59"
                    }
                },
                "scanner": "clamav"
            }
        ],
        "content_type": "malware",
        "imageDigest": "sha256:0eb874fcad5414762a2ca5b2496db5291aad7d3b737700d05e45af43bad3ce4d"
    }, [['clamav', "Unix.Trojan.MSShellcode-40", '/elf_payload1']]),
    ({
             "content": [
                 {
                     "enabled": True,
                     "findings": [
                         {
                             "path": "/elf_payload1",
                             "signature": "Unix.Trojan.MSShellcode-40"
                         },
                         {
                             "path": "/some/dir/path/corrupted",
                             "signature": "Unix.Trojan.MSShellcode-40"
                         }

                     ],
                     "metadata": {
                         "db_version": {
                             "bytecode": "331",
                             "daily": "25890",
                             "main": "59"
                         }
                     },
                     "scanner": "clamav"
                 }
             ],
             "content_type": "malware",
             "imageDigest": "sha256:0eb874fcad5414762a2ca5b2496db5291aad7d3b737700d05e45af43bad3ce4d"
         }, [['clamav', "Unix.Trojan.MSShellcode-40", '/elf_payload1'], ['clamav', "Unix.Trojan.MSShellcode-40", '/some/dir/path/corrupted']]),
    ({'content': []}, None)])
    def test_scan_results(self, content, expected):
        params = {'query_type': 'malware'}
        result = utils.format_malware_scans(content, params)
        assert result is not None
        if expected:
            t = utils.plain_column_table(['Scanner', 'Matched Signature', 'Path'])
            for r in expected:
                t.add_row(r)
            assert result == t.get_string(sortby='Path')



