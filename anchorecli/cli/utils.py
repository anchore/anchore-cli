import os
import re
import sys
import copy
import json
import yaml
import logging
import dateutil.parser
import textwrap
import base64

try:
    from urllib.parse import quote_plus, unquote_plus
except ImportError:
    from urllib import quote_plus, unquote_plus

from prettytable import PrettyTable, PLAIN_COLUMNS, ALL
from collections import OrderedDict

import anchorecli.clients.apiexternal

_logger = logging.getLogger(__name__)


def setup_config(cli_opts):
    ret = {
        "config": None,
        "user": None,
        "pass": None,
        "url": "http://localhost:8228/v1",
        "hub-url": "https://hub.anchore.io/",
        "api-version": None,
        "ssl_verify": True,
        "jsonmode": False,
        "debug": False,
        "as_account": None,
    }

    settings = {}

    # load environment if present
    for e in [
        "ANCHORE_CLI_USER",
        "ANCHORE_CLI_PASS",
        "ANCHORE_CLI_URL",
        "ANCHORE_CLI_HUB_URL",
        "ANCHORE_CLI_API_VERSION",
        "ANCHORE_CLI_SSL_VERIFY",
        "ANCHORE_CLI_JSON",
        "ANCHORE_CLI_DEBUG",
        "ANCHORE_CLI_ACCOUNT",
        "ANCHORE_CLI_CONFIG",
    ]:
        if e in os.environ:
            settings[e] = os.environ[e]

    # load up credentials file if present
    try:
        if "ANCHORE_CLI_CONFIG" in settings:
            credential_file = settings["ANCHORE_CLI_CONFIG"]
        else:
            home = os.path.expanduser("~")
            credential_file = os.path.join(home, ".anchore", "credentials.yaml")
        if os.path.exists(credential_file):
            ydata = {}
            with open(credential_file, "r") as FH:
                try:
                    ydata = yaml.safe_load(FH)
                except Exception as err:
                    raise Exception("YAML load failed: " + str(err))
            if ydata:
                try:
                    if type(ydata) != type(dict()):
                        raise Exception("invalid credentials file format")

                    default_creds = ydata.get("default", {})
                    for e in [
                        "ANCHORE_CLI_USER",
                        "ANCHORE_CLI_PASS",
                        "ANCHORE_CLI_URL",
                        "ANCHORE_CLI_HUB_URL",
                        "ANCHORE_CLI_API_VERSION",
                        "ANCHORE_CLI_SSL_VERIFY",
                    ]:
                        if e in default_creds:
                            settings[e] = default_creds[e]
                except Exception as err:
                    raise Exception(
                        "credentials file exists and has data, but cannot parse: "
                        + str(err)
                    )

    except Exception as err:
        raise Exception(
            "error while processing credentials file, please check format and read permissions - exception: "
            + str(err)
        )

    # load cmdline options
    if cli_opts["config"]:
        settings["ANCHORE_CLI_CONFIG"] = cli_opts["config"]
    if cli_opts["u"]:
        settings["ANCHORE_CLI_USER"] = cli_opts["u"]

    if cli_opts["p"]:
        settings["ANCHORE_CLI_PASS"] = cli_opts["p"]

    if cli_opts["url"]:
        settings["ANCHORE_CLI_URL"] = cli_opts["url"]

    if cli_opts["hub-url"]:
        settings["ANCHORE_CLI_HUB_URL"] = cli_opts["hub-url"]

    if cli_opts["api-version"]:
        settings["ANCHORE_CLI_API_VERSION"] = cli_opts["api-version"]

    if cli_opts["insecure"]:
        settings["ANCHORE_CLI_SSL_VERIFY"] = "n"

    if cli_opts["json"]:
        settings["ANCHORE_CLI_JSON"] = "y"

    if cli_opts["debug"]:
        settings["ANCHORE_CLI_DEBUG"] = "y"

    if cli_opts.get("as_account") is not None:
        settings["ANCHORE_CLI_ACCOUNT"] = cli_opts["as_account"]

    if "ANCHORE_CLI_CONFIG" in settings:
        ret["config"] = settings["ANCHORE_CLI_CONFIG"]
    if "ANCHORE_CLI_USER" in settings:
        ret["user"] = settings["ANCHORE_CLI_USER"]
    if "ANCHORE_CLI_PASS" in settings:
        ret["pass"] = settings["ANCHORE_CLI_PASS"]
    if "ANCHORE_CLI_URL" in settings:
        ret["url"] = settings["ANCHORE_CLI_URL"]
    if "ANCHORE_CLI_HUB_URL" in settings:
        ret["hub-url"] = settings["ANCHORE_CLI_HUB_URL"]

    if "ANCHORE_CLI_API_VERSION" in settings:
        ret["api-version"] = settings["ANCHORE_CLI_API_VERSION"]
    if "ANCHORE_CLI_SSL_VERIFY" in settings:
        if settings["ANCHORE_CLI_SSL_VERIFY"].lower() == "n":
            ret["ssl_verify"] = False
    if "ANCHORE_CLI_JSON" in settings:
        if settings["ANCHORE_CLI_JSON"].lower() == "y":
            ret["jsonmode"] = True
    if "ANCHORE_CLI_DEBUG" in settings:
        if settings["ANCHORE_CLI_DEBUG"].lower() == "y":
            ret["debug"] = True
    if "ANCHORE_CLI_ACCOUNT" in settings:
        ret["as_account"] = settings["ANCHORE_CLI_ACCOUNT"]

    return ret


def doexit(ecode):
    if not os.environ.get("ANCHORE_CLI_NO_FDS_CLEANUP"):
        try:
            sys.stdout.close()
        except Exception:
            pass
        try:
            sys.stderr.close()
        except Exception:
            pass
    sys.exit(ecode)


def group_list_of_dicts(indict, bykey):
    ret = []
    gdict = {}
    for el in indict:
        elkey = el[bykey]
        if elkey not in gdict:
            gdict[elkey] = []
        gdict[elkey].append(el)
    for k in list(gdict.keys()):
        for el in gdict[k]:
            ret.append(el)
    return ret


def format_error_output(config, op, params, payload):
    try:
        errdata = json.loads(str(payload))
    except ValueError:
        errdata = {"message": str(payload)}

    if config["jsonmode"]:
        return json.dumps(errdata, indent=4, sort_keys=True)

    obuf = ""
    outdict = OrderedDict()
    if "message" in errdata:
        outdict["Error"] = str(errdata["message"])
    if "httpcode" in errdata:
        outdict["HTTP Code"] = str(errdata["httpcode"])
    if "detail" in errdata and errdata["detail"]:
        outdict["Detail"] = str(errdata["detail"])

    for k in list(outdict.keys()):
        obuf = obuf + k + ": " + outdict[k] + "\n"

    if not obuf:
        obuf = str(payload)

    hint = create_hint(outdict.get("Detail"))
    if hint:
        obuf = obuf + hint
    # operation-specific output postfixes
    if op in ["account_delete"]:
        if "Invalid account state change requested" in errdata.get("message", ""):
            obuf = (
                obuf
                + "\nNOTE: accounts must be disabled (anchore-cli account disable <account>) in order to be deleted\n"
            )

    return obuf


def create_hint(error_message):
    """
    Apply some heuristics to determine if the message is a validation failure
    complaining about missing keys, if so, attempt to extract what may be the
    missing key, and craft a message that indicates how that might look inside
    a JSON object.

    :returns: multiline string on success, ``None`` on failure.
    """
    # when validation fails, the message already has something we can depend on
    # skip processing otherwise
    try:
        if "is a required property" not in error_message:
            return
    except TypeError:
        return

    pattern = re.compile(r"'(?P<key>.*?)'")
    search = re.search(pattern, error_message)
    if not search:
        return

    parsed = search.groupdict()
    key = parsed.get("key")
    if key:
        msg = (
            'Hint: The "{key}" key is not present in the JSON file, make sure it exists:\n\n'
            "    {{\n"
            '        "{key}": <value>\n'
            "        ...\n"
            "    }}\n"
        )
        return msg.format(key=key)


def plain_column_table(header, align="l"):
    table = PrettyTable(header)
    table.set_style(PLAIN_COLUMNS)
    table.align = align
    return table


def format_output(config, op, params, payload):
    if config["jsonmode"]:
        try:
            ret = json.dumps(payload, indent=4, sort_keys=True)
        # XXX catch json exception explicitly here
        except Exception:
            ret = json.dumps({"payload": str(payload)}, indent=4, sort_keys=True)
        return ret

    ret = ""
    try:
        if op == "image_list":

            if params["show_all"]:
                filtered_records = payload
            else:
                # this creates a filtered list w only the latest image records of any found tags
                latest_tag_details = {}
                latest_records = {}
                for image_record in payload:
                    for image_detail in image_record["image_detail"]:
                        fulltag = image_detail["fulltag"]
                        tagts = dateutil.parser.parse(image_detail["created_at"])
                        if fulltag not in latest_tag_details:
                            latest_tag_details[fulltag] = image_detail
                            latest_records[fulltag] = image_record
                        else:
                            lasttagts = dateutil.parser.parse(
                                latest_tag_details[fulltag]["created_at"]
                            )
                            if tagts >= lasttagts:
                                latest_tag_details[fulltag] = image_detail
                                latest_records[fulltag] = image_record

                filtered_records = list(latest_records.values())

            if params["full"]:
                header = ["Full Tag", "Image Digest", "Analysis Status", "Image ID"]
            else:
                header = ["Full Tag", "Image Digest", "Analysis Status"]

            t = plain_column_table(header)

            add_rows = []
            for image_record in filtered_records:
                for image_detail_record in image_record["image_detail"]:
                    image_detail = copy.deepcopy(image_detail_record)

                    imageId = fulltag = "None"

                    imageId = image_detail.pop("imageId", "None")
                    fulltag = (
                        image_detail.pop("registry", "None")
                        + "/"
                        + image_detail.pop("repo", "None")
                        + ":"
                        + image_detail.pop("tag", "None")
                    )

                    if params["full"]:
                        row = [
                            fulltag,
                            image_record["imageDigest"],
                            image_record["analysis_status"],
                            imageId,
                        ]
                    else:
                        row = [
                            fulltag,
                            image_record["imageDigest"],
                            image_record["analysis_status"],
                        ]
                    if row not in add_rows:
                        add_rows.append(row)
            for row in add_rows:
                t.add_row(row)
            ret = t.get_string(sortby="Full Tag")

        elif op == "image_vuln":
            ret = format_vulnerabilities(payload, params)

        elif op in ["image_content", "image_metadata"]:
            obuf = ""
            if "query_type" not in params or not params["query_type"]:
                outdict = OrderedDict()
                for t in payload:
                    outdict[t] = "available"
                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"
            else:
                if params["query_type"] == "os":
                    header = ["Package", "Version", "Licenses"]
                    t = plain_column_table(header)
                    for el in payload["content"]:
                        licenses = el.get("licenses", [el.get("license")])
                        row = [el["package"], el["version"], " ".join(licenses)]
                        t.add_row(row)
                    obuf = obuf + t.get_string(sortby="Package")
                elif params["query_type"] == "files":
                    header = ["Filename", "Size"]
                    t = plain_column_table(header)
                    for el in payload["content"]:
                        row = [el["filename"], el["size"]]
                        t.add_row(row)
                    obuf = obuf + t.get_string(sortby="Size", reversesort=True)
                elif params["query_type"] in ["npm", "gem", "python"]:
                    header = ["Package", "Version", "Location"]
                    t = plain_column_table(header)
                    for el in payload["content"]:
                        row = [el["package"], el["version"], el["location"]]
                        t.add_row(row)
                    obuf = obuf + t.get_string(sortby="Package")
                elif params["query_type"] in ["java"]:
                    header = [
                        "Package",
                        "Specification-Version",
                        "Implementation-Version",
                        "Location",
                    ]
                    t = plain_column_table(header)
                    for el in payload["content"]:
                        row = [
                            el["package"],
                            el["specification-version"],
                            el["implementation-version"],
                            el["location"],
                        ]
                        t.add_row(row)
                    obuf = obuf + t.get_string(sortby="Package")
                elif params["query_type"] in [
                    "manifest",
                    "dockerfile",
                    "docker_history",
                ]:
                    if op == "image_content":
                        obuf = format_content_query(payload)
                    else:
                        # Metadata Query. Note: The design of this whole method is bad, just doing the change in place
                        # to reduce changes for now, but should refactor this thing later
                        obuf = format_metadata_query(payload)
                elif params["query_type"] in ["malware"]:
                    obuf = format_malware_scans(payload, params)
                else:
                    try:
                        if payload["content"]:
                            el = payload["content"][0]
                            if (
                                el.get("package", None)
                                and el.get("version", None)
                                and el.get("location", None)
                            ):
                                header = ["Package", "Version", "Location"]
                                t = plain_column_table(header)
                                for el in payload["content"]:
                                    row = [el["package"], el["version"], el["location"]]
                                    t.add_row(row)
                                obuf = obuf + t.get_string(sortby="Package")
                            else:
                                header = list(el.keys())
                                t = PrettyTable(header)
                                t.set_style(PLAIN_COLUMNS)
                                t.align = "l"
                                for el in payload["content"]:
                                    row = []
                                    for k in header:
                                        row.append(el[k])
                                    t.add_row(row)
                                obuf = obuf + t.get_string()
                    except Exception as err:
                        raise Exception(
                            "could not parse content result - exception: " + str(err)
                        )

            ret = obuf
        elif op in ["image_add", "image_get", "image_import"]:
            obuf = ""
            for image_record in payload:
                outdict = OrderedDict()

                outdict["Image Digest"] = str(image_record["imageDigest"])
                if image_record.get("parentDigest", None):
                    outdict["Parent Digest"] = str(image_record["parentDigest"])
                outdict["Analysis Status"] = str(image_record["analysis_status"])
                outdict["Image Type"] = str(image_record["image_type"])
                outdict["Analyzed At"] = str(image_record["analyzed_at"])

                image_detail = copy.deepcopy(image_record["image_detail"][0])

                imageId = image_detail.pop("imageId", "None")
                outdict["Image ID"] = str(imageId)

                if "image_content" in image_record and image_record["image_content"]:
                    image_content = image_record["image_content"]
                    if "metadata" in image_content and image_content["metadata"]:
                        image_content_metadata = image_content["metadata"]
                        outdict["Dockerfile Mode"] = str(
                            image_content_metadata["dockerfile_mode"]
                        )
                        outdict["Distro"] = str(image_content_metadata["distro"])
                        outdict["Distro Version"] = str(
                            image_content_metadata["distro_version"]
                        )
                        outdict["Size"] = str(image_content_metadata["image_size"])
                        outdict["Architecture"] = str(image_content_metadata["arch"])
                        outdict["Layer Count"] = str(
                            image_content_metadata["layer_count"]
                        )

                if "annotations" in image_record and image_record["annotations"]:
                    outdict["Annotations"] = ", ".join(
                        [
                            str(x) + "=" + str(y)
                            for x, y in list(image_record["annotations"].items())
                        ]
                    )

                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

                for image_detail_record in image_record["image_detail"]:
                    image_detail = copy.deepcopy(image_detail_record)
                    outdict = OrderedDict()
                    outdict["Full Tag"] = str(image_detail.pop("fulltag", "None"))
                    outdict["Tag Detected At"] = str(
                        image_detail.pop("tag_detected_at", "None")
                    )

                    for k in list(outdict.keys()):
                        obuf = obuf + k + ": " + outdict[k] + "\n"
                    obuf = obuf + "\n"

            ret = obuf
        elif op in ["registry_add", "registry_get", "registry_update"]:
            obuf = ""
            for registry_record in payload:
                outdict = OrderedDict()

                outdict["Registry"] = str(registry_record["registry"])
                outdict["Name"] = str(registry_record.get("registry_name", "N/A"))
                outdict["User"] = str(registry_record["registry_user"])
                outdict["Type"] = str(registry_record["registry_type"])
                outdict["Verify TLS"] = str(registry_record["registry_verify"])
                outdict["Created"] = str(registry_record["created_at"])
                outdict["Updated"] = str(registry_record["last_updated"])

                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

            ret = obuf
        elif op == "registry_list":
            header = ["Registry", "Name", "Type", "User"]
            t = plain_column_table(header)
            for registry_record in payload:
                row = [
                    registry_record["registry"],
                    registry_record.get("registry_name", "N/A"),
                    registry_record["registry_type"],
                    registry_record["registry_user"],
                ]
                t.add_row(row)

            ret = t.get_string(sortby="Registry")
        elif op in ["subscription_list", "subscription_get"]:

            header = ["Tag", "Subscription Type", "Active"]

            if params.get("full", ""):
                header += ["Subscription ID"]
            if op == "subscription_get":
                header += ["User ID"]

            t = plain_column_table(header)
            for subscription_record in payload:
                row = [
                    subscription_record["subscription_key"],
                    subscription_record["subscription_type"],
                    str(subscription_record["active"]),
                ]
                if params.get("full", ""):
                    row.append(subscription_record.get("subscription_id", ""))
                if op == "subscription_get":
                    row += [subscription_record.get("userId")]
                t.add_row(row)

            ret = t.get_string(sortby="Tag")
        elif op == "repo_list":
            header = ["Repository", "Watched", "TagCount"]
            t = plain_column_table(header)
            for subscription_record in payload:
                try:
                    sval = json.loads(subscription_record["subscription_value"])
                    tagcount = str(sval["tagcount"])
                except Exception:
                    tagcount = "N/A"
                row = [
                    subscription_record["subscription_key"],
                    str(subscription_record["active"]),
                    str(tagcount),
                ]
                t.add_row(row)

            ret = t.get_string(sortby="Repository")
        elif op in ["repo_get", "repo_watch", "repo_unwatch", "repo_add"]:
            header = ["Repository", "Watched", "TagCount"]
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = "l"
            for subscription_record in payload:
                sval = json.loads(subscription_record["subscription_value"])
                tagcount = str(sval.get("tagcount", "N/A"))
                row = [
                    subscription_record["subscription_key"],
                    str(subscription_record["active"]),
                    tagcount,
                ]
                t.add_row(row)
            if params.get("dry_run", ""):
                ret = "DRY RUN: Repository not added\n\n"
            ret += t.get_string(sortby="Repository")
        elif op in ["policy_add", "policy_get"]:
            if "detail" in params and params["detail"]:
                try:
                    ret = json.dumps(
                        payload[0]["policybundle"], indent=4, sort_keys=True
                    )
                except Exception:
                    ret = json.dumps(payload, indent=4, sort_keys=True)
            else:
                obuf = ""

                if op == "policy_add":
                    payload = [payload]
                else:
                    pass

                for policy_record in payload:
                    outdict = OrderedDict()

                    outdict["Policy ID"] = str(policy_record["policyId"])
                    outdict["Active"] = str(policy_record["active"])
                    outdict["Source"] = str(policy_record["policy_source"])
                    outdict["Created"] = str(policy_record["created_at"])
                    outdict["Updated"] = str(policy_record["last_updated"])

                    for k in list(outdict.keys()):
                        obuf = obuf + k + ": " + outdict[k] + "\n"
                    obuf = obuf + "\n"

                ret = obuf

        elif op == "policy_list":
            header = ["Policy ID", "Active", "Created", "Updated"]
            t = plain_column_table(header)
            for policy_record in payload:
                row = [
                    policy_record["policyId"],
                    str(policy_record["active"]),
                    policy_record["created_at"],
                    policy_record["last_updated"],
                ]
                t.add_row(row)

            ret = t.get_string(sortby="Active", reversesort=True)

        elif op == "policy_hub_list":
            header = ["Name", "Description"]
            t = plain_column_table(header)
            for record in payload["content"]:
                if record.get("type", None) == "bundle":
                    row = [
                        textwrap.fill(record["name"], width=40),
                        textwrap.fill(record["description"], width=60),
                    ]
                    t.add_row(row)

            ret = t.get_string(sortby="Name", reversesort=True)
        elif op == "policy_hub_get":
            obuf = ""

            outdict = OrderedDict()

            outdict["Policy Bundle ID"] = str(payload["id"])
            outdict["Name"] = str(payload["name"])
            outdict["Description"] = str(
                payload.get("description", payload.get("comment", "N/A"))
            )
            for k in list(outdict.keys()):
                obuf = obuf + k + ": " + outdict[k] + "\n"
            obuf = obuf + "\n"

            id_to_name = {}
            for record in payload["policies"]:
                outdict = OrderedDict()
                outdict["Policy Name"] = record["name"]
                # outdict['Policy ID'] = record['id']
                outdict["Policy Description"] = str(
                    record.get("description", record.get("comment", "N/A"))
                )
                id_to_name[record["id"]] = record["name"]
                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

            for record in payload["whitelists"]:
                outdict = OrderedDict()
                outdict["Whitelist Name"] = record["name"]
                # outdict['Whitelist ID'] = record['id']
                outdict["Whitelist Description"] = str(
                    record.get("description", record.get("comment", "N/A"))
                )
                id_to_name[record["id"]] = record["name"]
                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

            for record in payload["mappings"]:
                outdict = OrderedDict()
                outdict["Mapping Name"] = record["name"]
                outdict["Mapping Rule"] = "{}/{}:{}".format(
                    record["registry"], record["repository"], record["image"]["value"]
                )
                pids = []
                pid = record.get("policy_id", None)
                if pid:
                    pids.append(pid)
                pids = [str(id_to_name[x]) for x in pids + record.get("policy_ids", [])]
                outdict["Mapping Policies"] = ",".join(pids)
                wids = [str(id_to_name[x]) for x in record.get("whitelist_ids", [])]
                outdict["Mapping Whitelists"] = ",".join(wids)
                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

            ret = obuf
            # ret = json.dumps(payload, indent=4, sort_keys=True)
        elif op == "evaluate_check":
            obuf = ""

            for eval_record in payload:
                outdict = OrderedDict()

                for imageDigest in list(eval_record.keys()):
                    for fulltag in eval_record[imageDigest]:
                        if not eval_record[imageDigest][fulltag]:
                            outdict["Image Digest"] = str(imageDigest)
                            outdict["Full Tag"] = str(fulltag)
                            outdict["Status"] = "no_eval_available"
                            for k in list(outdict.keys()):
                                obuf = obuf + k + ": " + outdict[k] + "\n"
                            obuf = obuf + "\n"
                        else:
                            for evaldata in eval_record[imageDigest][fulltag]:
                                outdict["Image Digest"] = str(imageDigest)
                                outdict["Full Tag"] = str(fulltag)
                                if "detail" in params and params["detail"]:
                                    evaldetail = evaldata["detail"]
                                    outdict["Image ID"] = str(
                                        evaldetail["result"]["image_id"]
                                    )
                                outdict["Status"] = str(evaldata["status"])
                                outdict["Last Eval"] = str(evaldata["last_evaluation"])
                                outdict["Policy ID"] = str(evaldata["policyId"])

                                t = None
                                if "detail" in params and params["detail"]:
                                    evaldetail = evaldata["detail"]
                                    imageId = evaldetail["result"]["image_id"]

                                    try:
                                        outdict["Final Action"] = str(
                                            evaldetail["result"]["final_action"]
                                        )
                                        outdict["Final Action Reason"] = str(
                                            evaldetail["result"]["final_action_reason"]
                                        )
                                    except:
                                        pass

                                    evalresults = evaldetail["result"]["result"][
                                        imageId
                                    ]["result"]
                                    header = ["Gate", "Trigger", "Detail", "Status"]
                                    t = plain_column_table(header)
                                    for row in evalresults["rows"]:
                                        if "full" in params and params["full"]:
                                            detailrow = row[5]
                                        else:
                                            detailrow = row[5]

                                        status_detail = row[6]
                                        try:
                                            if row[7]:
                                                eval_whitelist_detail = row[7]
                                                status_detail = (
                                                    "whitelisted("
                                                    + eval_whitelist_detail[
                                                        "whitelist_name"
                                                    ]
                                                    + ")"
                                                )
                                        except:
                                            status_detail = row[6]

                                        newrow = [
                                            row[3],
                                            row[4],
                                            detailrow,
                                            status_detail,
                                        ]
                                        t.add_row(newrow)

                                for k in list(outdict.keys()):
                                    obuf = obuf + k + ": " + outdict[k] + "\n"
                                if t:
                                    obuf = obuf + "\n"
                                    obuf = obuf + t.get_string() + "\n"

            ret = obuf
        elif op == "policy_activate":
            try:
                ret = "Success: " + str(params["policyId"]) + " activated"
            except Exception:
                ret = "Success"
        elif op == "system_status":
            out_list = []
            db_version = code_version = None
            for service_record in payload.get("service_states", []):
                if service_record.get("status", None):
                    service_status = "up"
                else:
                    service_status = "down ({})".format(
                        service_record.get("status_message", "Status Unknown")
                    )

                out_list.append(
                    "Service {} ({}, {}): {}".format(
                        service_record.get("servicename", "ServiceName Unknown"),
                        service_record.get("hostid", "HostID Unknown"),
                        service_record.get("base_url", "Base URL Unknown"),
                        str(service_status),
                    )
                )

                # This is a fallback mechanism to get the db & code versions from a non-api service
                # (should there be no healthy api service available)
                if not db_version:
                    db_version = service_record.get("service_detail", {}).get(
                        "db_version", None
                    )
                if not code_version:
                    code_version = service_record.get("service_detail", {}).get(
                        "version", None
                    )

                # Set the code & db versions with the details from the first discovered API service that is up
                if (
                    service_record.get("servicename", "") == "apiext"
                    and service_status == "up"
                ):
                    service_detail = service_record.get("service_detail", {})
                    code_version = service_detail.get("version", None)
                    db_version = service_detail.get("db_version", None)

            output_buffer = "\n".join(out_list)
            output_buffer += "\n\nEngine DB Version: {}\n".format(
                db_version or "Not Found"
            )
            output_buffer += "Engine Code Version: {}".format(
                code_version or "Not Found"
            )

            ret = output_buffer

        elif op == "event_delete":
            if payload is not None and isinstance(payload, list):
                ret = (
                    "Deleted {} events".format(len(payload))
                    if payload
                    else "No matching events found"
                )
            else:
                ret = "Success"
        elif op in ["describe_gates"]:
            ret = _format_gates(payload, all=params.get("all", False))
        elif op in ["describe_gate_triggers"]:
            ret = _format_triggers(
                payload, params.get("gate", "").lower(), all=params.get("all", False)
            )
        elif op in ["describe_gate_trigger_params"]:
            ret = _format_trigger_params(
                payload,
                params.get("gate", "").lower(),
                params.get("trigger", "").lower(),
                all=params.get("all", False),
            )
        elif op in ["system_describe_error_codes"]:
            header = ["Error Code", "Description"]
            t = plain_column_table(header)
            for el in payload:
                error_name = el.get("name", "N/A")
                error_description = textwrap.fill(
                    el.get("description", "N/A"), width=60
                )
                t.add_row([error_name, error_description])
            ret = t.get_string(sortby="Error Code") + "\n"
        elif op in ["system_feeds_list"]:
            header = ["Feed", "Group", "LastSync", "RecordCount"]
            t = plain_column_table(header)
            for el in payload:
                feed = el.get("name", "N/A")
                feed_enabled = el.get("enabled", True)
                if not feed_enabled:
                    feed = "{}(disabled)".format(feed)
                for gel in el["groups"]:
                    group_enabled = gel.get("enabled", True)
                    last_sync = gel.get("last_sync", None)
                    if not last_sync:
                        if feed_enabled and group_enabled:
                            last_sync = "pending"
                        else:
                            last_sync = "-"

                    gname = gel.get("name", "N/A")
                    if not group_enabled:
                        gname = "{}(disabled)".format(gname)
                    t.add_row([feed, gname, last_sync, gel.get("record_count", "N/A")])
            ret = t.get_string(sortby="Feed") + "\n"
        elif op in ["system_feed_groups"]:
            header = ["Group", "LastSync", "RecordCount"]
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = "l"
            for gel in payload:
                last_sync = gel.get("last_sync", None)
                if not last_sync:
                    last_sync = "pending"
                gname = gel.get("name", "N/A")
                if not gel.get("enabled", True):
                    gname = "{}(disabled)".format(gname)
                t.add_row([gname, last_sync, gel.get("record_count", "N/A")])
            ret = t.get_string(sortby="Group") + "\n"
        elif op in ["system_feeds_flush"]:
            ret = "Success"
            if type(payload) == list:
                header = ["Feed", "Group", "Status", "Records Updated", "Sync Duration"]
                t = plain_column_table(header)
                for feed in payload:
                    for group in feed.get("groups"):
                        row = [
                            feed["feed"],
                            group["group"],
                            group["status"],
                            group["updated_record_count"],
                            "{:.2f}s".format(group["total_time_seconds"]),
                        ]
                        t.add_row(row)
                ret = t.get_string(sortby="Feed")
        elif op == "event_list":
            header = ["Timestamp", "Level", "Event", "Resource", "ID"]
            t = plain_column_table(header)
            for event_res in payload["results"]:
                event = event_res["event"]
                row = [
                    event["timestamp"],
                    event["level"],
                    event["type"],
                    event["resource"].get("id"),
                    event_res["generated_uuid"],
                ]
                t.add_row(row)
            ret = t.get_string()
        elif op == "event_list_full":
            header = [
                "Timestamp",
                "Level",
                "Event",
                "ResourceType",
                "Resource",
                "Service",
                "Host",
                "ID",
            ]
            t = plain_column_table(header)
            for event_res in payload["results"]:
                event = event_res["event"]
                row = [
                    event["timestamp"],
                    event["level"],
                    event["type"],
                    event["resource"].get("type"),
                    event["resource"].get("id"),
                    event["source"]["servicename"],
                    event["source"]["hostid"],
                    event_res["generated_uuid"],
                ]
                t.add_row(row)
            ret = t.get_string()
        elif op == "event_get":
            ret = yaml.safe_dump(payload["event"], default_flow_style=False)
        elif op == "query_images_by_vulnerability":
            header = [
                "Full Tag",
                "Severity",
                "Package",
                "Package Type",
                "Namespace",
                "Digest",
            ]
            t = plain_column_table(header)
            for record in payload.get("images", []):
                for tag_record in record.get("image", {}).get("tag_history", []):
                    for package_record in record.get("vulnerable_packages", []):
                        row = [
                            tag_record.get("fulltag", "N/A"),
                            package_record.get("severity", "N/A"),
                            "{}-{}".format(
                                package_record.get("name"),
                                package_record.get("version"),
                            ),
                            package_record.get("type"),
                            package_record.get("namespace", "N/A"),
                            record.get("image", {}).get("imageDigest", "N/A"),
                        ]
                        t.add_row(row)
            ret = t.get_string()
        elif op == "query_images_by_package":
            header = ["Full Tag", "Package", "Package Type", "Digest"]
            t = plain_column_table(header)
            for record in payload.get("images", []):
                for tag_record in record.get("image", {}).get("tag_history", []):
                    for package_record in record.get("packages", []):
                        row = [
                            tag_record.get("fulltag", "N/A"),
                            "{}-{}".format(
                                package_record.get("name"),
                                package_record.get("version"),
                            ),
                            package_record.get("type"),
                            record.get("image", {}).get("imageDigest", "N/A"),
                        ]
                        t.add_row(row)
            ret = t.get_string()
        elif op == "account_whoami":
            outdict = OrderedDict()

            outdict["Username"] = str(payload.get("user", {}).get("username", "N/A"))
            outdict["AccountName"] = str(payload.get("account", {}).get("name", "N/A"))
            outdict["AccountEmail"] = str(
                payload.get("account", {}).get("email", "N/A")
            )
            outdict["AccountType"] = str(payload.get("account", {}).get("type", "N/A"))

            obuf = ""
            for k in list(outdict.keys()):
                obuf = obuf + k + ": " + outdict[k] + "\n"
            obuf = obuf + "\n"

            ret = obuf
        elif op in ["account_add", "account_get"]:
            outdict = OrderedDict()

            outdict["Name"] = str(payload.get("name", "N/A"))
            outdict["Email"] = str(payload.get("email", "N/A"))
            outdict["Type"] = str(payload.get("type", "N/A"))
            outdict["State"] = str(payload.get("state", "N/A"))
            outdict["Created"] = str(payload.get("created_at", "N/A"))

            obuf = ""
            for k in list(outdict.keys()):
                obuf = obuf + "{}: {}\n".format(k, outdict[k])
            obuf = obuf + "\n"

            ret = obuf
        elif op in ["account_list"]:
            header = ["Name", "Email", "Type", "State", "Created"]
            t = plain_column_table(header)
            for record in payload:
                row = [
                    str(record.get("name", "N/A")),
                    str(record.get("email", "N/A")),
                    str(record.get("type", "N/A")),
                    str(record.get("state", "N/A")),
                    str(record.get("created_at", "N/A")),
                ]
                t.add_row(row)
            ret = t.get_string(sortby="Created") + "\n"

        elif op in ["user_add", "user_get"]:
            outdict = OrderedDict()

            outdict["Name"] = str(payload.get("username", "N/A"))
            outdict["Type"] = str(payload.get("type", "N/A"))
            outdict["Source"] = str(payload.get("source", "N/A"))
            outdict["Created"] = str(payload.get("created_at", "N/A"))

            obuf = ""
            for k in list(outdict.keys()):
                obuf = obuf + "{}: {}\n".format(k, outdict[k])
            obuf = obuf + "\n"

            ret = obuf
        elif op in ["user_list"]:
            header = ["Name", "Type", "Source", "Created"]
            t = plain_column_table(header)
            for record in payload:
                row = [
                    str(record.get("username", "N/A")),
                    str(record.get("type", "N/A")),
                    str(record.get("source", "N/A")),
                    str(record.get("created_at", "N/A")),
                ]
                t.add_row(row)
            ret = t.get_string(sortby="Created") + "\n"
        elif op in ["user_setpassword"]:
            ret = "Password (re)set success"
        elif (
            op in ["delete_system_service"]
            or re.match(".*_delete$", op)
            or re.match(".*_activate$", op)
            or re.match(".*_deactivate$", op)
            or re.match(".*_enable$", op)
            or re.match(".*_disable$", op)
        ):
            # NOTE this should always be the last in the if/elif conditional
            ret = "Success"
        elif op in ["analysis_archive_list", "archived_analysis"]:
            header = [
                "Digest",
                "Tags",
                "Analyzed At",
                "Archived At",
                "Status",
                "Archive Size Bytes",
            ]
            t = plain_column_table(header)
            for record in payload:
                row = [
                    str(record["imageDigest"]),
                    str(
                        ",".join(
                            [x["pullstring"] for x in record.get("image_detail", [])]
                        )
                    ),
                    str(record["analyzed_at"]),
                    str(record["created_at"]),
                    str(record["status"]),
                    str(record["archive_size_bytes"]),
                ]
                t.add_row(row)
            ret = t.get_string(sortby="Archived At", reversesort=True) + "\n"
        elif op in ["archive_analysis"]:
            header = ["Image Digest", "Archive Status", "Details"]
            t = plain_column_table(header)
            for record in payload:
                row = [
                    str(record["digest"]),
                    str(record["status"]),
                    str(record["detail"]),
                ]
                t.add_row(row)
            ret = t.get_string(sortby="Archive Status") + "\n"
        elif op in ["transition_rules"]:
            header = [
                "Rule Id",
                "Global",
                "Transition",
                "Analysis Age (Days)",
                "Tag Versions Newer",
                "Registry",
                "Repository",
                "Tag",
                "Max Images",
                "Registry Exclude",
                "Repo Exclude",
                "Tag Exclude",
                "Exclude Exp Days",
                "Last Updated",
            ]
            t = plain_column_table(header)
            if type(payload) != list:
                payload = [payload]
            for record in payload:
                row = [
                    str(record["rule_id"]),
                    str(record["system_global"]),
                    str(record["transition"]),
                    str(record["analysis_age_days"]),
                    str(record["tag_versions_newer"]),
                    str(record["selector"]["registry"]),
                    str(record["selector"]["repository"]),
                    str(record["selector"]["tag"]),
                    str(record["max_images_per_account"]),
                    str(record["exclude"]["selector"]["registry"]),
                    str(record["exclude"]["selector"]["repository"]),
                    str(record["exclude"]["selector"]["tag"]),
                    str(record["exclude"]["expiration_days"]),
                    str(record["last_updated"]),
                ]
                t.add_row(row)
            ret = t.get_string(sortby="Last Updated", reversesort=True) + "\n"
        elif op in ["transition_rule_history"]:
            header = ["Rule Id", "Image Digest", "Transition", "Transition Date"]
            t = plain_column_table(header)
            for record in payload:
                row = [
                    str(record["rule_id"]),
                    str(record["imageDigest"]),
                    str(record["transition"]),
                    str(record["created_at"]),
                ]
                t.add_row(row)
            ret = t.get_string(sortby="Transition Date", reversesort=True) + "\n"
        elif op in ["list_corrections"]:
            header = ["ID", "Match", "Replace", "Created At", "Description"]
            t = plain_column_table(header)
            for record in payload:
                row = [
                    str(record["uuid"]),
                    str(record["match"]),
                    str(record["replace"]),
                    str(record["created_at"]),
                    str(record["description"]),
                ]
                t.add_row(row)
            ret = t.get_string(sortby="Created At", reversesort=True) + "\n"
        elif op in ["get_correction"]:
            ret = (
                "UUID: %s\nMatch: %s\nReplace: %s\nCreated At: %s\nDescription: %s\n"
                % (
                    str(payload["uuid"]),
                    str(payload["match"]),
                    str(payload["replace"]),
                    str(payload["created_at"]),
                    str(payload["description"]),
                )
            )
        elif (
            op
            in [
                "delete_system_service",
                "test_webhook",
                "add_correction",
                "delete_correction",
            ]
            or re.match(".*_delete$", op)
            or re.match(".*_activate$", op)
            or re.match(".*_deactivate$", op)
            or re.match(".*_enable$", op)
            or re.match(".*_disable$", op)
        ):
            # NOTE this should always be the last in the if/elif conditional
            ret = "Success"
        else:
            raise Exception("no output handler for this operation ({})".format(op))
    except Exception as err:
        print(
            "WARNING: failed to format output (returning raw output) - exception: "
            + str(err)
        )
        try:
            ret = json.dumps(payload, indent=4, sort_keys=True)
        # XXX catch json errors here
        except Exception:
            ret = str(payload)
    return ret


def format_malware_scans(payload, params):
    """
    Example response:
    {
        "content": [
            {
                "enabled": true,
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
    }

    :param payload:
    :param params:
    :return:
    """
    obuf = ""

    # Handle error
    if "query_type" not in params or not params["query_type"]:
        # payload will be a list with what is available as a query for the
        # given image
        for query in payload:
            obuf += "%s: available\n" % query
        return obuf + "\n"

    if params["query_type"] in ["malware"]:
        header = ["Scanner", "Matched Signature", "Path"]
        t = plain_column_table(header)
        for el in payload["content"]:
            scanner = el.get("scanner")
            for row in [
                [scanner, x.get("signature", "unknown"), x.get("path", "unknown")]
                for x in el.get("findings", {})
            ]:
                t.add_row(row)
        obuf = obuf + t.get_string(sortby="Path")

    return obuf


def format_vulnerabilities(payload, params):
    obuf = ""
    if "query_type" not in params or not params["query_type"]:
        # payload will be a list with what is available as a query for the
        # given image
        for query in payload:
            obuf += "%s: available\n" % query
        return obuf + "\n"

    if params["query_type"] in ["os", "non-os", "all"]:
        header = [
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
        t = plain_column_table(header)
        for el in payload["vulnerabilities"]:
            nvd_data = el.get("nvd_data")
            cve_ids = []
            for nvd_record in nvd_data:
                _id = nvd_record.get("id")
                if _id:
                    cve_ids.append(_id)
            row = [
                el["vuln"],
                el["package"],
                el["severity"],
                el["fix"],
                ",".join(cve_ids),
                el["url"],
                el["package_type"],
                el["feed_group"],
                el["package_path"],
            ]
            t.add_row(row)
        obuf = obuf + t.get_string(sortby="Severity")

    return obuf


def format_content_query(payload):
    content = payload.get("content", "")
    if not content:
        return ""
    if isinstance(content, list):
        # In some situations the `content` key can be a list, not a string
        content = "".join(content)
    try:
        return base64.b64decode(content).decode("utf-8")
    except Exception:
        # This broad exception catching is warranted here because there are all
        # sort of warts we would need to catch with utf-8 decoding and
        # b64decode. The actual exception is not that relevant here
        return ""


def format_metadata_query(payload):
    ret = ""

    if not payload:
        return ret

    image_digest = payload.get("imageDigest", "")
    if image_digest:
        ret += "Image Digest: {}\n".format(image_digest)

    metadata = payload.get("metadata", "")
    if metadata:
        try:
            ret += "Metadata: {}\n".format(base64.b64decode(metadata).decode("utf-8"))
        except Exception:
            _logger.warning("Failed to base64 decode Metadata")
            pass

    metadata_type = payload.get("metadata_type", "")
    if metadata_type:
        ret += "Metadata Type: {}\n".format(metadata_type)

    return ret


def string_splitter(input_str, max_length=40):
    """
    Returns a string that is the input string but with \n inserted every max_length chars

    :param input_str:
    :param max_length: int num of chars between \n
    :return: string
    """

    chunks = []
    chunk = ""
    pieces = input_str.split(" ")

    for piece in pieces:
        if len(chunk) + len(piece) < max_length:
            chunk = " ".join([chunk, piece])
        else:
            chunks.append(chunk)
            chunk = piece
    chunks.append(chunk)

    return "\n".join(chunks).strip()


def _format_gates(payload, all=False):
    if not all:
        header = ["Gate", "Description"]
    else:
        header = ["Gate", "Description", "State", "Superceded By"]

    t = PrettyTable(header, hrules=ALL)
    t.align = "l"

    if payload:
        for gate in payload:
            desc = string_splitter(gate.get("description", ""), 60)
            if all:
                t.add_row(
                    [
                        gate["name"].lower(),
                        desc,
                        gate.get("state", ""),
                        gate.get("superceded_by", ""),
                    ]
                )
            elif gate.get("state") in [None, "active"]:
                t.add_row([gate["name"].lower(), desc])

        return t.get_string(sortby="Gate", print_empty=True)
    else:
        return "No policy spec to parse"


def _format_triggers(payload, gate, all=False):
    if not all:
        header = ["Trigger", "Description", "Parameters"]
    else:
        header = ["Trigger", "Description", "Parameters", "State", "Superceded By"]
    t = PrettyTable(header, hrules=ALL)
    t.align = "l"

    if payload:
        for gate in [x for x in payload if x["name"].lower() == gate]:
            for trigger_entry in gate.get("triggers", []):
                desc = string_splitter(trigger_entry.get("description", ""))
                param_str = string_splitter(
                    ", ".join(
                        [x["name"].lower() for x in trigger_entry.get("parameters", [])]
                    ),
                    max_length=20,
                )
                if all:
                    t.add_row(
                        [
                            trigger_entry["name"].lower(),
                            desc,
                            param_str,
                            trigger_entry.get("state", ""),
                            trigger_entry.get("superceded_by", ""),
                        ]
                    )
                elif trigger_entry.get("state") in [None, "active"]:
                    t.add_row([trigger_entry["name"].lower(), desc, param_str])

        return t.get_string(sortby="Trigger", print_empty=True)
    else:
        return "No policy spec to parse"


def _format_trigger_params(payload, gate, trigger, all=False):
    if all:
        header = [
            "Parameter",
            "Description",
            "Required",
            "Example",
            "State",
            "Supereceded By",
        ]
    else:
        header = ["Parameter", "Description", "Required", "Example"]
    t = PrettyTable(header, hrules=ALL)
    t.align = "l"

    if payload:
        for gate in [x for x in payload if x["name"].lower() == gate]:
            for trigger_entry in [
                x for x in gate.get("triggers", []) if x["name"].lower() == trigger
            ]:
                for p in trigger_entry.get("parameters", []):
                    desc = string_splitter(p.get("description", ""))
                    if all:
                        t.add_row(
                            [
                                p["name"].lower(),
                                desc,
                                p.get("required", True),
                                p.get("example", ""),
                                p.get("state", ""),
                                p.get("superceded_by", ""),
                            ]
                        )
                    elif p.get("state") in [None, "active"]:
                        t.add_row(
                            [
                                p["name"].lower(),
                                desc,
                                p.get("required", True),
                                p.get("example", ""),
                            ]
                        )

        return t.get_string(sortby="Parameter", print_empty=True)
    else:
        return "No policy spec to parse"


def get_eval_ecode(evaldata, imageDigest):
    # 0 aid tag 0 status
    ret = 2
    try:
        fulltag = list(evaldata[0][imageDigest].keys())[0]
        status = evaldata[0][imageDigest][fulltag][0]["status"].lower()
        if status == "pass":
            ret = 0
        elif status == "fail":
            ret = 1
        else:
            raise Exception("got unknown eval status result: " + str(status))
    except Exception:
        ret = 2
    return ret


def get_ecode(response):
    ecode = 2
    try:
        httpcode = response["httpcode"]
        _logger.debug("fetched httpcode from response: %s", str(httpcode))
        if httpcode in range(200, 299):
            ecode = 0
        elif httpcode in [401, 500]:
            ecode = 2
        else:
            ecode = 1
    except Exception:
        pass

    return ecode


def check_access(config):
    # test the endpoint
    try:
        rc = anchorecli.clients.apiexternal.get_base_routes(config)
        if not rc["success"]:
            raise Exception(json.dumps(rc["error"], sort_keys=True))
    except Exception as err:
        if config["debug"]:
            raise Exception(
                "could not access anchore service (user="
                + str(config["user"])
                + " url="
                + str(config["url"])
                + "): "
                + str(err)
            )
        else:
            raise Exception(
                "could not access anchore service (user="
                + str(config["user"])
                + " url="
                + str(config["url"])
                + ")"
            )

    return True


def discover_inputimage_format(config, input_string):
    itype = None

    if re.match("(sha256|local):[0-9a-fA-F]{64}", input_string):
        itype = "imageDigest"
    elif re.match("[0-9a-fA-F]{64}", input_string):
        itype = "imageid"
    else:
        itype = "tag"

    return itype


def discover_inputimage(config, input_string):
    patt = re.match("(.*@|^)(sha256:.*)", input_string)
    if patt:
        urldigest = quote_plus(patt.group(2))
        return ("digest", input_string, urldigest)

    try:
        digest = unquote_plus(str(input_string))
        patt = re.match("(.*@|^)(sha256:.*)", digest)
        if patt:
            return ("imageDigest", input_string, input_string)
        patt = re.match("(.*@|^)(local:.*)", digest)
        if patt:
            return ("imageDigest", input_string, input_string)
    except Exception:
        pass

    urldigest = None
    ret_type = "tag"
    try:
        ret = anchorecli.clients.apiexternal.get_image(config, tag=input_string)
        if ret["success"]:
            urldigest = ret["payload"][0]["imageDigest"]
            try:
                image_record = ret["payload"][0]
                for image_detail in image_record["image_detail"]:
                    if input_string == image_detail["imageId"]:
                        ret_type = "imageid"
                        break
            except Exception:
                pass
        else:
            pass
    except Exception:
        urldigest = None

    return ret_type, input_string, urldigest


def parse_dockerimage_string(instr):
    host = None
    port = None
    repo = None
    tag = None
    registry = None
    repotag = None
    fulltag = None
    fulldigest = None
    digest = None
    imageId = None

    if re.match("^sha256:.*", instr):
        registry = "docker.io"
        digest = instr

    elif len(instr) == 64 and not re.findall("[^0-9a-fA-F]+", instr):
        imageId = instr
    else:

        # get the host/port
        patt = re.match("(.*?)/(.*)", instr)
        if patt:
            a = patt.group(1)
            remain = patt.group(2)
            patt = re.match("(.*?):(.*)", a)
            if patt:
                host = patt.group(1)
                port = patt.group(2)
            elif a == "docker.io":
                host = "docker.io"
                port = None
            elif a in ["localhost", "localhost.localdomain", "localbuild"]:
                host = a
                port = None
            else:
                patt = re.match(".*\..*", a)
                if patt:
                    host = a
                else:
                    host = "docker.io"
                    remain = instr
                port = None

        else:
            host = "docker.io"
            port = None
            remain = instr

        # get the repo/tag
        patt = re.match("(.*)@(.*)", remain)
        if patt:
            repo = patt.group(1)
            digest = patt.group(2)
        else:
            patt = re.match("(.*):(.*)", remain)
            if patt:
                repo = patt.group(1)
                tag = patt.group(2)
            else:
                repo = remain
                tag = "latest"

        if not tag:
            tag = "latest"

        if port:
            registry = ":".join([host, port])
        else:
            registry = host

        if digest:
            repotag = "@".join([repo, digest])
        else:
            repotag = ":".join([repo, tag])

        fulltag = "/".join([registry, repotag])

        if not digest:
            digest = None
        else:
            fulldigest = registry + "/" + repo + "@" + digest
            tag = None
            fulltag = None
            repotag = None

    ret = {}
    ret["host"] = host
    ret["port"] = port
    ret["repo"] = repo
    ret["tag"] = tag
    ret["registry"] = registry
    ret["repotag"] = repotag
    ret["fulltag"] = fulltag
    ret["digest"] = digest
    ret["fulldigest"] = fulldigest
    ret["imageId"] = imageId

    if ret["fulldigest"]:
        ret["pullstring"] = ret["fulldigest"]
    elif ret["fulltag"]:
        ret["pullstring"] = ret["fulltag"]
    else:
        ret["pullstring"] = None

    return ret
