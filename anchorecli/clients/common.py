import json


def _safe_loads(text):
    try:
        return json.loads(text)
    except Exception:
        return text


def make_client_result(response, raw=False):
    ret = {"success": False, "httpcode": 0, "payload": {}, "error": {}}

    ret["httpcode"] = response.status_code

    if response.status_code in range(200, 299):
        ret["success"] = True
        if raw is True:
            ret["payload"] = response.text
        else:
            ret["payload"] = _safe_loads(response.text)

    else:
        ret["success"] = False

        if raw is True:
            ret["error"] = response.text
        else:
            ret["error"] = _safe_loads(response.text)

        if not ret.get("error", None) and response.status_code in [401]:
            ret["error"] = "Unauthorized - please check your username/password"

    return ret
