import re
import requests
import urllib3
import requests.packages.urllib3

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import anchorecli.clients.common


def _get_hub_index(config, auth=(None, None)):
    base_url = re.sub("/$", "", config["hub-url"])

    index = {}
    url = "{}/index.json".format(base_url)
    try:
        r = requests.get(url, auth=auth)
        if r.status_code not in range(200, 299):
            raise Exception(
                "Could not fetch index from {} - server responded with {}".format(
                    url, r
                )
            )
        else:
            index = r.json()
    except Exception as err:
        raise err
    return index


def _fetch_bundle(config, bundlename=None, auth=(None, None)):
    base_url = re.sub("/$", "", config["hub-url"])

    ret = anchorecli.clients.hub.get_policies(config)
    if ret["success"]:
        index = ret["payload"]
    else:
        raise Exception(ret["error"])

    url = None
    for record in index["content"]:
        if record["type"] == "bundle" and record["name"] == bundlename:
            url = base_url + "/" + record["location"]

    if not url:
        raise Exception("Bundle name {} not found in index".format(bundlename))

    bundle = None
    r = requests.get(url, auth=auth)
    if r.status_code not in range(200, 299):
        raise Exception(
            "Could not fetch bundle from {} - server responded with {}".format(url, r)
        )
    else:
        bundle = r.json()

    return bundle


def get_policy(config, bundlename, auth=(None, None)):
    ret = {
        "success": False,
        "payload": {},
        "httpcode": 500,
    }

    try:
        bundle = _fetch_bundle(config, bundlename=bundlename, auth=auth)
        ret["payload"] = bundle
        ret["httpcode"] = 200
        ret["success"] = True
    except Exception as err:
        ret["success"] = False
        ret["error"] = str(err)

    return ret


def get_policies(config, auth=(None, None)):
    ret = {
        "success": False,
        "payload": {},
        "httpcode": 500,
    }

    try:
        index = _get_hub_index(config, auth=auth)
        ret["success"] = True
        ret["payload"] = index
        ret["httpcode"] = 200
    except Exception as err:
        ret["success"] = False
        ret["error"] = str(err)

    return ret


def install_policy(config, bundlename, target_id=None, force=False, auth=(None, None)):
    ret = {
        "success": False,
        "payload": {},
        "httpcode": 500,
    }

    try:
        bundle = _fetch_bundle(config, bundlename=bundlename, auth=auth)

        if target_id:
            bundleid = target_id
        else:
            bundleid = bundle["name"]
        bundle["id"] = bundleid

        if not force:
            ret = anchorecli.clients.apiexternal.get_policies(config)
            if ret["success"]:
                for installed_policy in ret["payload"]:
                    if installed_policy["policyId"] == bundleid:
                        raise Exception(
                            "Policy with ID ({}) already installed - use force to override or specify target unique ID".format(
                                bundleid
                            )
                        )

        ret = anchorecli.clients.apiexternal.add_policy(
            config, policybundle=bundle, detail=True
        )

    except Exception as err:
        ret["success"] = False
        ret["error"] = str(err)

    return ret
