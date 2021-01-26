import json
import os
import re
import requests
import logging
import urllib3
import requests.packages.urllib3

try:
    from urllib.parse import urlparse, urlunparse, urlencode, quote
except ImportError:
    from urllib import urlencode, quote
    from urlparse import urlparse, urlunparse

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import anchorecli.clients.common

_logger = logging.getLogger(__name__)

header_overrides = {"Content-Type": "application/json"}


def set_account_header(config):
    _logger.debug("As Account = %s", config.get("as_account"))
    if config["as_account"] is not None:
        header_overrides["x-anchore-account"] = config["as_account"]
    else:
        header_overrides.pop("x-anchore-account", None)


def get_base_routes(config):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}
    set_account_header(config)

    try:
        r = requests.get(
            base_url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


# system clients
def system_feeds_list(config):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system/feeds"])
    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        _logger.debug("GET insecure=%s", str(config["ssl_verify"]))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def system_feeds_sync(config, flush=False):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system/feeds?flush={}".format(flush)])
    set_account_header(config)
    try:
        _logger.debug("POST url=%s", str(url))
        _logger.debug("POST insecure=%s", str(config["ssl_verify"]))
        r = requests.post(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def system_feed_enable_toggle(config, feed, enabled):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system/feeds/{}?enabled={}".format(feed, enabled)])
    set_account_header(config)
    try:
        _logger.debug("PUT url=%s", str(url))
        _logger.debug("PUT insecure=%s", str(config["ssl_verify"]))
        r = requests.put(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def system_feed_group_enable_toggle(config, feed, group, enabled):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join(
        [base_url, "system/feeds/{}/{}?enabled={}".format(feed, group, enabled)]
    )
    set_account_header(config)
    try:
        _logger.debug("PUT url=%s", str(url))
        _logger.debug("PUT insecure=%s", str(config["ssl_verify"]))
        r = requests.put(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def system_feed_delete(config, feed):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system/feeds/{}".format(feed)])
    set_account_header(config)
    try:
        _logger.debug("DELETE url=%s", str(url))
        _logger.debug("DELETE insecure=%s", str(config["ssl_verify"]))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def system_feed_group_delete(config, feed, group):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system/feeds/{}/{}".format(feed, group)])
    set_account_header(config)
    try:
        _logger.debug("DELETE url=%s", str(url))
        _logger.debug("DELETE insecure=%s", str(config["ssl_verify"]))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def system_status(config):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system"])
    set_account_header(config)
    try:
        _logger.debug("GET url=%s", str(url))
        _logger.debug("GET insecure=%s", str(config["ssl_verify"]))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def delete_system_service(config, host_id, servicename):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    if not host_id or not servicename:
        raise Exception("invalid host_id or servicename given")

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system", "services", servicename, host_id])
    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


# image clients


def add_image(
    config,
    tag=None,
    digest=None,
    dockerfile=None,
    force=False,
    annotations={},
    autosubscribe=True,
):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    payload = {}
    if dockerfile:
        payload["dockerfile"] = dockerfile

    if digest:
        payload["digest"] = digest
    elif tag:
        payload["tag"] = tag
    else:
        return False

    if annotations:
        payload["annotations"] = annotations

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "images"])

    url = url + "?autosubscribe=" + str(autosubscribe)
    if force:
        url = url + "&force=true"

    set_account_header(config)

    try:
        _logger.debug("POST url=%s", str(url))
        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def restore_archived_image(config, digest):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    payload = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "images"])

    set_account_header(config)

    payload = {"source": {"archive": {"digest": digest}}}
    try:
        _logger.debug("POST url=%s", str(url))
        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def detect_api_version(config):
    """
    Returns the api version for the service as a tuple of ints. E.g '0.1.1' -> (0, 1, 1)
    :param config:
    :return: tuple of ints
    """
    if config["api-version"]:
        return tuple([int(x) for x in config["api-version"].split(".")])

    userId = config["user"]
    password = config["pass"]

    # contruct candidate URLs for finding the anchore-engine swagger.json document, supporting indirection through proxies and base anchore-engine service
    urls = []
    try:
        url = urlparse(config["url"])
        url = urlunparse(
            (
                url.scheme,
                url.netloc,
                "/swagger.json",
                url.params,
                url.query,
                url.fragment,
            )
        )
        urls.append(url)
    except:
        pass

    try:
        url = "/".join([re.sub("/$", "", config["url"]), "swagger.json"])
        urls.append(url)
    except:
        pass

    for url in urls:
        # Detect if we can use query params or must use the GET body
        version = None
        try:
            resp = requests.get(
                url,
                auth=(userId, password),
                verify=config["ssl_verify"],
                headers=header_overrides,
            )
            if not resp or not resp.json().get("info").get("version"):
                pass
            else:
                version = tuple(
                    [int(x) for x in resp.json().get("info").get("version").split(".")]
                )
        except:
            pass

        if version:
            return version

    return tuple([0])


def get_image(config, tag=None, image_id=None, imageDigest=None, history=False):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]
    api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "images"])

    if imageDigest:
        url += "/{}".format(imageDigest)
    elif image_id:
        url += "/by_id/{}".format(image_id)
    elif tag:
        params["fulltag"] = tag
    else:
        return False

    if history:
        params["history"] = "true"
    else:
        params["history"] = "false"

    if api_version < api_version_query_support and tag:
        payload = {"tag": params.pop("fulltag")}
    else:
        payload = None

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        _logger.debug("GET params=%s", str(params))
        _logger.debug(
            "Use get body because detected api version %s < %s? %s",
            api_version,
            api_version_query_support,
            (payload is not None),
        )
        _logger.debug("GET insecure=%s", str(config["ssl_verify"]))
        if payload:
            r = requests.get(
                url,
                data=json.dumps(payload),
                params=params,
                auth=(userId, password),
                verify=config["ssl_verify"],
                headers=header_overrides,
            )
        else:

            r = requests.get(
                url,
                params=params,
                auth=(userId, password),
                verify=config["ssl_verify"],
                headers=header_overrides,
            )

        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def get_images(config):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    _logger.info("Base = %s", base_url)
    url = "/".join([base_url, "images"])
    _logger.info("Url = %s", url)
    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def import_image(config, anchore_data=[]):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = []

    payload = anchore_data[0]

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "imageimport"])
    set_account_header(config)

    try:
        _logger.debug("POST url=%s", str(url))

        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def query_image(
    config, imageDigest=None, query_group=None, query_type=None, vendor_only=True
):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "images", imageDigest])

    if query_group:
        url = "/".join([url, query_group])
    else:
        raise Exception("need to specify a query group")

    if query_type:
        url = "/".join([url, query_type])

    if query_group == "vuln":
        url = url + "?vendor_only={}".format(vendor_only)

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def delete_image(config, imageDigest=None, force=False):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    if not imageDigest:
        raise Exception("must specify a valid imageDigest to delete")

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "images", imageDigest])

    if force:
        url = url + "?force=True"

    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


# policy clients


def add_policy(config, policybundle={}, detail=False):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    payload = policybundle

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "policies"])

    if detail:
        url = url + "?detail=True"
    else:
        url = url + "?detail=False"

    set_account_header(config)

    try:
        _logger.debug("POST url=%s", str(url))
        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def get_policy(config, policyId=None, detail=False):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    if policyId:
        url = "/".join([base_url, "policies", policyId])
    else:
        return False

    if detail:
        url = url + "?detail=True"
    else:
        url = url + "?detail=False"

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)

    except Exception as err:
        raise err

    return ret


def get_policies(config, detail=False):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "policies"])

    if detail:
        url = url + "?detail=True"
    else:
        url = url + "?detail=False"

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def update_policy(config, policyId, policy_record={}):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "policies", policyId])

    payload = policy_record
    set_account_header(config)

    try:
        _logger.debug("PUT url=%s", str(url))
        r = requests.put(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def delete_policy(config, policyId):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "policies", policyId])
    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


# eval clients


def check_eval(
    config, imageDigest=None, history=False, detail=False, tag=None, policyId=None
):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "images", imageDigest, "check"])
    if history:
        url = url + "?history=true"
    else:
        url = url + "?history=false"
    if detail:
        url = url + "&detail=true"
    else:
        url = url + "&detail=false"

    if tag:
        url = url + "&tag=" + str(tag)

    if policyId:
        url = url + "&policyId=" + str(policyId)

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


# subscription clients


def activate_subscription(config, subscription_type, subscription_key):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    # first - get the subscription record from engine, to get the right subscription_id for the record
    try:
        subscription_response = get_subscription(
            config, subscription_type, subscription_key
        )
        subscription_records = subscription_response.get("payload", [])
        if not subscription_records:
            raise Exception(
                "cannot locate subscription record using specified input (subscription_type={}, subscription_key={} needs to exist before activation)".format(
                    subscription_type, subscription_key
                )
            )
        subscription_record = subscription_records[0]
    except Exception as err:
        raise err

    subscription_id = subscription_record.get("subscription_id", None)
    if not subscription_id:
        raise Exception(
            "could not get a valid subscription record using specified input"
        )

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "subscriptions", subscription_id])

    payload = {
        "active": True,
        "subscription_key": subscription_key,
        "subscription_type": subscription_type,
    }
    set_account_header(config)

    try:
        _logger.debug("PUT url=%s", str(url))
        r = requests.put(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def deactivate_subscription(config, subscription_type, subscription_key):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    # first - get the subscription record from engine, to get the right subscription_id for the record
    try:
        subscription_response = get_subscription(
            config, subscription_type, subscription_key
        )
        subscription_records = subscription_response.get("payload", [])
        if not subscription_records:
            raise Exception(
                "cannot locate subscription record using specified input (subscription_type={}, subscription_key={} needs to exist before deactivation)".format(
                    subscription_type, subscription_key
                )
            )
        subscription_record = subscription_records[0]
    except Exception as err:
        raise err

    subscription_id = subscription_record.get("subscription_id", None)
    if not subscription_id:
        raise Exception(
            "could not get a valid subscription record using specified input"
        )

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "subscriptions", subscription_id])

    payload = {
        "active": False,
        "subscription_key": subscription_key,
        "subscription_type": subscription_type,
    }
    set_account_header(config)

    try:
        _logger.debug("PUT url=%s", str(url))
        r = requests.put(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def add_subscription(config, subscription_type, subscription_key, active=True):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "subscriptions"])

    payload = {
        "active": active,
        "subscription_key": subscription_key,
        "subscription_type": subscription_type,
    }
    set_account_header(config)

    try:
        _logger.debug("POST url=%s", str(url))
        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def delete_subscription(config, subscription_type=None, subscription_key=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    # first - get the subscription record from engine, to get the right subscription_id for the record
    try:
        subscription_response = get_subscription(
            config, subscription_type, subscription_key
        )
        subscription_records = subscription_response.get("payload", [])
        if not subscription_records:
            raise Exception(
                "cannot locate subscription record using specified input (subscription_type={}, subscription_key={} needs to exist before deletion)".format(
                    subscription_type, subscription_key
                )
            )
        subscription_record = subscription_records[0]
    except Exception as err:
        raise err

    subscription_id = subscription_record.get("subscription_id", None)
    if not subscription_id:
        raise Exception(
            "could not get a valid subscription record using specified input"
        )

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "subscriptions", subscription_id])
    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def get_subscription(config, subscription_type=None, subscription_key=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    url = os.path.join(base_url, "subscriptions")
    set_account_header(config)

    query = {}
    if subscription_key:
        query["subscription_key"] = subscription_key
    if subscription_type:
        query["subscription_type"] = subscription_type

    _logger.debug("GET url=%s", str(url))
    r = requests.get(
        url,
        auth=(userId, password),
        verify=config["ssl_verify"],
        headers=header_overrides,
        params=query,
    )
    return anchorecli.clients.common.make_client_result(r, raw=False)


def get_subscription_by_id(config, subscription_id):
    user_id = config["user"]
    password = config["pass"]
    base_url = config["url"]

    url = os.path.join(base_url, "subscriptions", subscription_id)
    _logger.debug("GET url=%s", str(url))
    r = requests.get(
        url,
        auth=(user_id, password),
        verify=config["ssl_verify"],
        headers=header_overrides,
    )
    return anchorecli.clients.common.make_client_result(r, raw=False)


def delete_subscription_by_id(config, subscription_id):
    user_id = config["user"]
    password = config["pass"]
    base_url = config["url"]

    url = os.path.join(base_url, "subscriptions", subscription_id)
    _logger.debug("DELETE url=%s", str(url))
    r = requests.delete(
        url,
        auth=(user_id, password),
        verify=config["ssl_verify"],
        headers=header_overrides,
    )
    return anchorecli.clients.common.make_client_result(r, raw=False)


def get_subscription_types(config):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "subscriptions", "types"])
    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def add_repo(config, input_repo, auto_subscribe=False, lookup_tag=None, dry_run=False):
    user_id = config["user"]
    password = config["pass"]
    base_url = config["url"]

    url = os.path.join(base_url, "repositories")

    query = {
        "repository": input_repo,
        "autosubscribe": str(auto_subscribe),
        "dryrun": str(dry_run),
    }
    if lookup_tag:
        query["lookuptag"] = lookup_tag

    set_account_header(config)

    _logger.debug("POST url=%s", str(url))
    r = requests.post(
        url,
        auth=(user_id, password),
        verify=config["ssl_verify"],
        headers=header_overrides,
        params=query,
    )
    return anchorecli.clients.common.make_client_result(r, raw=False)


def get_repo(config, input_repo=None):
    set_account_header(config)

    filtered_records = []
    subscriptions = get_subscription(config, subscription_type="repo_update")
    subscription_records = subscriptions["payload"]
    for i in range(0, len(subscription_records)):
        subscription_record = subscription_records[i]
        if subscription_record["subscription_type"] == "repo_update":
            if not input_repo or subscription_record["subscription_key"] == input_repo:
                filtered_records.append(subscription_record)

    subscriptions["payload"] = filtered_records

    return subscriptions


def delete_repo(config, input_repo, force=False):
    return delete_subscription(config, "repo_update", input_repo)


def watch_repo(config, input_repo):
    return activate_subscription(config, "repo_update", input_repo)


def unwatch_repo(config, input_repo):
    return deactivate_subscription(config, "repo_update", input_repo)


# interactive clients


def interactive_query(config, payload={}):
    return interactive(config, "query", payload=payload)


def interactive_analyze(config, payload={}):
    return interactive(config, "analyze", payload=payload)


def interactive_evaluate(config, payload={}):
    return interactive(config, "evaluate", payload=payload)


def interactive(config, op_type, payload={}):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "interactive", op_type])
    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


# registry clients


def get_registry(config, registry=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "registries"])
    if registry:
        url = "/".join([url, quote(registry, "")])

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def add_registry(
    config,
    registry=None,
    registry_user=None,
    registry_pass=None,
    registry_type=None,
    insecure=False,
    validate=True,
    registry_name=None,
):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "registries"])
    url = "{}?validate={}".format(url, validate)

    payload = {}
    verify = not insecure
    payload.update(
        {
            "registry": registry,
            "registry_user": registry_user,
            "registry_pass": registry_pass,
            "registry_type": registry_type,
            "registry_verify": verify,
            "registry_name": registry_name,
        }
    )
    set_account_header(config)

    try:
        _logger.debug("POST url=%s", str(url))
        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def update_registry(
    config,
    registry=None,
    registry_user=None,
    registry_pass=None,
    registry_type=None,
    insecure=False,
    validate=True,
    registry_name=None,
):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "registries", quote(registry, "")])
    url = "{}?validate={}".format(url, validate)

    payload = {}
    verify = not insecure
    payload.update(
        {
            "registry": registry,
            "registry_user": registry_user,
            "registry_pass": registry_pass,
            "registry_type": registry_type,
            "registry_verify": verify,
            "registry_name": registry_name,
        }
    )
    set_account_header(config)

    try:
        _logger.debug("PUT url=%s", str(url))
        r = requests.put(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def delete_registry(config, registry=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "registries", quote(registry, "")])
    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def describe_error_codes(config):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system", "error_codes"])
    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def describe_policy_spec(config):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system", "policy_spec"])
    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def list_events(
    config,
    since=None,
    before=None,
    level=None,
    service=None,
    host=None,
    resource=None,
    resource_type=None,
    event_type=None,
    all=False,
):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "events"])

    if since:
        params["since"] = since

    if before:
        params["before"] = before

    if level:
        params["level"] = level

    if service:
        params["source_servicename"] = service

    if host:
        params["source_hostid"] = host

    if resource:
        params["resource_id"] = resource

    if event_type:
        params["event_type"] = event_type

    if resource_type:
        params["resource_type"] = resource_type

    set_account_header(config)

    try:
        if all:
            # Results might be paginated here, so loop
            events = []
            while True:
                if ret and ret["payload"]["next_page"] is True:
                    params["page"] = int(ret["payload"]["page"]) + 1

                _logger.debug("GET url=%s", str(url))
                _logger.debug("GET params=%s", str(params))
                _logger.debug("GET insecure=%s", str(config["ssl_verify"]))

                r = requests.get(
                    url,
                    params=params,
                    auth=(userId, password),
                    verify=config["ssl_verify"],
                    headers=header_overrides,
                )
                ret = anchorecli.clients.common.make_client_result(r, raw=False)

                if ret["success"]:
                    events += ret["payload"]["results"]
                    ret["payload"]["results"] = events
                else:
                    break

                if ret["payload"]["next_page"] is False:
                    break
        else:
            _logger.debug("GET url=%s", str(url))
            _logger.debug("GET params=%s", str(params))
            _logger.debug("GET insecure=%s", str(config["ssl_verify"]))

            r = requests.get(
                url,
                params=params,
                auth=(userId, password),
                verify=config["ssl_verify"],
                headers=header_overrides,
            )
            ret = anchorecli.clients.common.make_client_result(r, raw=False)

    except Exception as err:
        raise err

    return ret


def get_event(config, event_id):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "events", event_id])
    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        _logger.debug("GET insecure=%s", str(config["ssl_verify"]))

        r = requests.get(
            url,
            params=params,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def delete_events(config, since=None, before=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "events"])

    if since:
        params["since"] = since

    if before:
        params["before"] = before

    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        _logger.debug("DELETE params=%s", str(params))
        _logger.debug("DELETE insecure=%s", str(config["ssl_verify"]))

        r = requests.delete(
            url,
            params=params,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def delete_event(config, event_id):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "events", event_id])
    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        _logger.debug("DELETE insecure=%s", str(config["ssl_verify"]))

        r = requests.delete(
            url,
            params=params,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def query_images_by_vulnerability(
    config,
    vulnerability_id,
    namespace=None,
    affected_package=None,
    severity=None,
    vendor_only=True,
):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = "/".join(
        [
            base_url,
            "query/images/by_vulnerability?vulnerability_id={}".format(
                vulnerability_id
            ),
        ]
    )

    query_params = {}
    if namespace:
        query_params["namespace"] = namespace
    if affected_package:
        query_params["affected_package"] = affected_package
    if severity:
        query_params["severity"] = severity
    if vendor_only:
        query_params["vendor_only"] = vendor_only

    if query_params:
        url = "{}&{}".format(url, urlencode(query_params))

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        _logger.debug("GET insecure=%s", str(config["ssl_verify"]))

        r = requests.get(
            url,
            params=params,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def query_images_by_package(config, name, version=None, package_type=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "query/images/by_package?name={}".format(name)])

    query_params = {}
    if version:
        query_params["version"] = version
    if package_type:
        query_params["package_type"] = package_type

    if query_params:
        url = "{}&{}".format(url, urlencode(query_params))

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        _logger.debug("GET insecure=%s", str(config["ssl_verify"]))

        r = requests.get(
            url,
            params=params,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


# account clients


def add_account(config, account_name=None, email=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "accounts"])

    payload = {}

    payload.update({"name": account_name})
    if email:
        payload["email"] = email

    set_account_header(config)

    try:
        _logger.debug("POST url=%s", str(url))
        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def get_account(config, account_name=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    set_account_header(config)

    if account_name:
        url = "/".join([base_url, "accounts", quote(account_name, "")])
    else:
        url = "/".join([base_url, "account"])

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def list_accounts(config):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "accounts"])
    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def del_account(config, account_name=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "accounts", quote(account_name, "")])
    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def enable_account(config, account_name=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "accounts", quote(account_name, ""), "state"])

    payload = {}
    payload.update({"state": "enabled"})
    set_account_header(config)

    try:
        _logger.debug("PUT url=%s", str(url))
        r = requests.put(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def disable_account(config, account_name=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "accounts", quote(account_name, ""), "state"])

    payload = {}
    payload.update({"state": "disabled"})
    set_account_header(config)

    try:
        _logger.debug("PUT url=%s", str(url))
        r = requests.put(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


# user clients


def add_user(config, account_name=None, user_name=None, user_password=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "accounts", quote(account_name, ""), "users"])

    payload = {}
    payload.update({"username": user_name, "password": user_password})
    set_account_header(config)

    try:
        _logger.debug("POST url=%s", str(url))
        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def get_user(config, account_name=None, user_name=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    if account_name and user_name:
        url = "/".join(
            [
                base_url,
                "accounts",
                quote(account_name, ""),
                "users",
                quote(user_name, ""),
            ]
        )
    elif not account_name and not user_name:
        url = "/".join([base_url, "user"])
    else:
        return ret

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def del_user(config, account_name=None, user_name=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join(
        [base_url, "accounts", quote(account_name, ""), "users", quote(user_name, "")]
    )

    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def list_users(config, account_name=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    if account_name:
        url = "/".join([base_url, "accounts", quote(account_name, ""), "users"])

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def update_user_password(config, account_name=None, user_name=None, user_password=None):
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join(
        [
            base_url,
            "accounts",
            quote(account_name, ""),
            "users",
            quote(user_name, ""),
            "credentials",
        ]
    )

    payload = {}
    payload.update({"type": "password", "value": user_password})
    set_account_header(config)

    try:
        _logger.debug("POST url=%s", str(url))
        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def list_archives(config):
    """
    GET /archives

    :param config:
    :return:
    """
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives"])

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def list_archived_analyses(config):
    """
    GET /archives/images

    :param config:
    :return:
    """
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives", "images"])

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def get_archived_analysis(config, digest):
    """
    GET /archives/images/{digest}

    :param config:
    :param digest:
    :return:
    """
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives", "images", digest])

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def archive_analyses(config, digests):
    """
    POST /archives/images

    Payload: [digest1, digest2,..., digestN]

    :param config:
    :param digest:
    :return:
    """
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives", "images"])

    set_account_header(config)

    try:
        _logger.debug("POST url=%s", str(url))
        r = requests.post(
            url,
            data=json.dumps(list(digests)),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def delete_archived_analysis(config, digest):
    """
    DELETE /archives/images/{digest}

    :param config:
    :param digest:
    :return:
    """
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives", "images", digest])

    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def list_transition_rules(config):
    """
    GET /archives/rules

    :param config:
    :return:
    """
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives", "rules"])

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def get_transition_rule(config, rule_id):
    """
    GET /archives/rules/{rule_id}

    :param config:
    :return:
    """
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives", "rules", rule_id])

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def delete_transition_rule(config, rule_id):
    """
    DELETE /archives/rules/{rule_id}

    :param config:
    :return:
    """
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives", "rules", rule_id])

    set_account_header(config)

    try:
        _logger.debug("DELETE url=%s", str(url))
        r = requests.delete(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def get_transition_rule_history(config, rule_id):
    """
    GET /archives/rules/{rule_id}/history

    :param config:
    :return:
    """
    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives", "rules", rule_id, "history"])

    set_account_header(config)

    try:
        _logger.debug("GET url=%s", str(url))
        r = requests.get(
            url,
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def add_transition_rule(
    config,
    analysis_age_days,
    tag_versions_newer=0,
    selector_registry="*",
    selector_repository="*",
    selector_tag="*",
    transition="archive",
    is_global=False,
    max_images_per_account=None,
    registry_exclude="",
    repository_exclude="",
    tag_exclude="",
    exclude_expiration_days="-1",
):
    """
    POST /archives/rules

    :param config:
    :param analysis_age_days: Number of days the analysis has been in the engine (int)
    :param tag_versions_newer: Number of newer digest mappings for the tag in the anchore db
    :param selector_registry: Wild-card supported string to match registry (e.g. 'docker.io', '*', or '*amazonaws.com')
    :param selector_repository: Wild-card supported string to match registry (e.g. 'docker.io', '*', or '*amazonaws.com')
    :param selector_tag: Wild-card supported string to match registry (e.g. 'docker.io', '*', or '*amazonaws.com')
    :param transition: which transition to use, either 'archive' or 'delete'
    :param is_global: should the rule be a global rule (bool)
    :param max_images_per_account: the maximum number of images per account (must be only
    :param registry_exclude: registries to exclude from archiving
    :param repository_exclude:  repositories to exclude from archiving
    :param tag_exclude: tags to exclude from archiving
    :param exclude_expiration_days: number of days until exclude expires
    :return:
    """

    userId = config["user"]
    password = config["pass"]
    base_url = config["url"]

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "archives", "rules"])

    set_account_header(config)

    if transition not in ["archive", "delete"]:
        raise ValueError('transiton must be one of "archive" or "delete"')

    if type(analysis_age_days) != int:
        raise TypeError("analysis_age_days must be an integer")

    if type(tag_versions_newer) != int:
        raise TypeError("tag_versions_newer must be an integer")

    payload = {
        "tag_versions_newer": tag_versions_newer,
        "analysis_age_days": analysis_age_days,
        "transition": transition,
        "system_global": is_global,
    }

    if max_images_per_account:
        payload.update(
            {
                "max_images_per_account": max_images_per_account,
            }
        )
    else:
        payload.update(
            {
                "selector": {
                    "registry": selector_registry,
                    "repository": selector_repository,
                    "tag": selector_tag,
                },
                "exclude": {
                    "expiration_days": exclude_expiration_days,
                    "selector": {
                        "registry": registry_exclude,
                        "repository": repository_exclude,
                        "tag": tag_exclude,
                    },
                },
            }
        )

    try:
        _logger.debug("POST url=%s", str(url))
        _logger.debug(json.dumps(payload))
        r = requests.post(
            url,
            data=json.dumps(payload),
            auth=(userId, password),
            verify=config["ssl_verify"],
            headers=header_overrides,
        )
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return ret


def test_webhook(config, webhook_type="general", notification_type="tag_update"):
    """
    Calls the API to test whether or not a webhook is correctly configured

    :param config: the configuration to retrieve request metadata from
    :param webhook_type: the type of webhook to test (defaults to general)
    """
    user = config["user"]
    pw = config["pass"]
    base_url = config["url"]

    base_url = re.sub("/$", "", base_url)
    url = "/".join([base_url, "system", "webhooks", webhook_type, "test"])

    url = url + "?notification_type={}".format(notification_type)

    set_account_header(config)

    _logger.debug("POST url=%s", str(url))
    r = requests.post(
        url, auth=(user, pw), verify=config["ssl_verify"], headers=header_overrides
    )
    ret = anchorecli.clients.common.make_client_result(r, raw=False)

    return ret


def render_url(config, path_parts):
    base_url = config["url"]

    base_url = re.sub("/$", "", base_url)

    path_parts.insert(0, base_url)
    return "/".join(path_parts)


def enterprise_add_correction(config, correction):
    user = config["user"]
    pw = config["pass"]

    url = render_url(config, ["enterprise", "corrections"])

    set_account_header(config)

    _logger.debug("POST url=%s", str(url))
    r = requests.post(
        url,
        auth=(user, pw),
        verify=config["ssl_verify"],
        headers=header_overrides,
        data=json.dumps(correction),
    )
    ret = anchorecli.clients.common.make_client_result(r, raw=False)

    return ret


def enterprise_get_correction(config, correction_id):
    user = config["user"]
    pw = config["pass"]

    url = render_url(config, ["enterprise", "corrections", correction_id])

    set_account_header(config)

    _logger.debug("GET url=%s", str(url))
    r = requests.get(
        url, auth=(user, pw), verify=config["ssl_verify"], headers=header_overrides
    )
    ret = anchorecli.clients.common.make_client_result(r, raw=False)

    return ret


def enterprise_list_corrections(config):
    user = config["user"]
    pw = config["pass"]

    url = render_url(config, ["enterprise", "corrections"])

    set_account_header(config)

    _logger.debug("GET url=%s", str(url))
    r = requests.get(
        url, auth=(user, pw), verify=config["ssl_verify"], headers=header_overrides
    )
    ret = anchorecli.clients.common.make_client_result(r, raw=False)

    return ret


def enterprise_delete_correction(config, correction_id):
    user = config["user"]
    pw = config["pass"]

    url = render_url(config, ["enterprise", "corrections", correction_id])

    set_account_header(config)

    _logger.debug("DELETE url=%s", str(url))
    r = requests.delete(
        url, auth=(user, pw), verify=config["ssl_verify"], headers=header_overrides
    )
    ret = anchorecli.clients.common.make_client_result(r, raw=False)

    return ret
