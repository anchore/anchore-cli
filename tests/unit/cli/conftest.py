import pytest


@pytest.fixture
def payload():
    return {
        "imageDigest": "sha256:285bc3161133ec01d8ca8680cd746eecbfdbc1faa6313bd863151c4b26d7e5a5",
        "vulnerabilities": [
            {
                "feed": "vulnerabilities",
                "feed_group": "centos:7",
                "fix": "0:3.44.0-7.el7_7",
                "nvd_data": [
                    {
                        "cvss_v2": {
                            "base_score": 5.0,
                            "exploitability_score": 10.0,
                            "impact_score": 2.9,
                        },
                        "cvss_v3": {
                            "base_score": 7.5,
                            "exploitability_score": 3.9,
                            "impact_score": 3.6,
                        },
                        "id": "CVE-2019-11729",
                    },
                    {
                        "cvss_v2": {
                            "base_score": 6.8,
                            "exploitability_score": 8.6,
                            "impact_score": 6.4,
                        },
                        "cvss_v3": {
                            "base_score": -1.0,
                            "exploitability_score": -1.0,
                            "impact_score": -1.0,
                        },
                        "id": "CVE-2019-11745",
                    },
                ],
                "package": "nss-3.44.0-4.el7",
                "package_cpe": "None",
                "package_cpe23": "None",
                "package_name": "nss",
                "package_path": "None",
                "package_type": "rpm",
                "package_version": "3.44.0-4.el7",
                "severity": "High",
                "url": "https://access.redhat.com/errata/RHSA-2019:4190",
                "vendor_data": [],
                "vuln": "RHSA-2019:4190",
            },
            {
                "feed": "vulnerabilities",
                "feed_group": "centos:7",
                "fix": "0:3.44.0-7.el7_7",
                "nvd_data": [
                    {
                        "cvss_v2": {
                            "base_score": 5.0,
                            "exploitability_score": 10.0,
                            "impact_score": 2.9,
                        },
                        "cvss_v3": {
                            "base_score": 7.5,
                            "exploitability_score": 3.9,
                            "impact_score": 3.6,
                        },
                        "id": "CVE-2019-11729",
                    },
                    {
                        "cvss_v2": {
                            "base_score": 6.8,
                            "exploitability_score": 8.6,
                            "impact_score": 6.4,
                        },
                        "cvss_v3": {
                            "base_score": -1.0,
                            "exploitability_score": -1.0,
                            "impact_score": -1.0,
                        },
                        "id": "CVE-2019-11745",
                    },
                ],
                "package": "nss-sysinit-3.44.0-4.el7",
                "package_cpe": "None",
                "package_cpe23": "None",
                "package_name": "nss-sysinit",
                "package_path": "None",
                "package_type": "rpm",
                "package_version": "3.44.0-4.el7",
                "severity": "High",
                "url": "https://access.redhat.com/errata/RHSA-2019:4190",
                "vendor_data": [],
                "vuln": "RHSA-2019:4190",
            },
            {
                "feed": "vulnerabilities",
                "feed_group": "centos:7",
                "fix": "0:3.44.0-4.el7_7",
                "nvd_data": [
                    {
                        "cvss_v2": {
                            "base_score": 5.0,
                            "exploitability_score": 10.0,
                            "impact_score": 2.9,
                        },
                        "cvss_v3": {
                            "base_score": 7.5,
                            "exploitability_score": 3.9,
                            "impact_score": 3.6,
                        },
                    },
                    {
                        "cvss_v2": {
                            "base_score": 6.8,
                            "exploitability_score": 8.6,
                            "impact_score": 6.4,
                        },
                        "cvss_v3": {
                            "base_score": -1.0,
                            "exploitability_score": -1.0,
                            "impact_score": -1.0,
                        },
                        "id": "CVE-2019-11745",
                    },
                ],
                "package": "nss-util-3.44.0-3.el7",
                "package_cpe": "None",
                "package_cpe23": "None",
                "package_name": "nss-util",
                "package_path": "None",
                "package_type": "rpm",
                "package_version": "3.44.0-3.el7",
                "severity": "High",
                "url": "https://access.redhat.com/errata/RHSA-2019:4190",
                "vendor_data": [],
                "vuln": "RHSA-2019:4190",
            },
        ],
        "vulnerability_type": "os",
    }
