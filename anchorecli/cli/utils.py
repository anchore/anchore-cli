import os
import re
import sys
import copy
import json
import yaml
import logging
import dateutil.parser
import struct

try:
    from urllib.parse import quote_plus,unquote_plus
except:
    from urllib import quote_plus,unquote_plus

from prettytable import PrettyTable, PLAIN_COLUMNS, ALL
from collections import OrderedDict
#from textwrap import fill

import anchorecli.clients.apiexternal

_logger = logging.getLogger(__name__)

def setup_config(cli_opts):
    ret = {
        'user':None,
        'pass':None,
        'url':"http://localhost:8228/v1",
        'api-version': None,
        'ssl_verify':True,
        'jsonmode':False,
        'debug':False,
    }

    settings = {}

    # load up credentials file if present
    try:
        home = os.environ.get('HOME', None)
        credential_file = os.path.join(home, '.anchore', 'credentials.yaml')
        if os.path.exists(credential_file):
            ydata = {}
            with open(credential_file, 'r') as FH:
                try:
                    ydata = yaml.safe_load(FH)
                except Exception as err:
                    raise Exception("YAML load failed: " + str(err))
            if ydata:
                try:
                    if type(ydata) != type(dict()):
                        raise Exception("invalid credentials file format")

                    default_creds = ydata.get('default', {})
                    for e in ['ANCHORE_CLI_USER', 'ANCHORE_CLI_PASS', 'ANCHORE_CLI_URL', 'ANCHORE_CLI_API_VERSION', 'ANCHORE_CLI_SSL_VERIFY']:
                        if e in default_creds:
                            settings[e] = default_creds[e]
                except Exception as err:
                    raise Exception("credentials file exists and has data, but cannot parse: " + str(err))

    except Exception as err:
        raise Exception("error while processing credentials file, please check format and read permissions - exception: " + str(err))
    
    # load environment if present
    try:
        for e in ['ANCHORE_CLI_USER', 'ANCHORE_CLI_PASS', 'ANCHORE_CLI_URL', 'ANCHORE_CLI_API_VERSION', 'ANCHORE_CLI_SSL_VERIFY', 'ANCHORE_CLI_JSON', 'ANCHORE_CLI_DEBUG']:
            if e in os.environ:
                settings[e] = os.environ[e]
    except Exception as err:
        raise err

    # load cmdline options
    try:
        if cli_opts['u']:
            settings['ANCHORE_CLI_USER'] = cli_opts['u']

        if cli_opts['p']:
            settings['ANCHORE_CLI_PASS'] = cli_opts['p']

        if cli_opts['url']:
            settings['ANCHORE_CLI_URL'] = cli_opts['url']

        if cli_opts['api-version']:
            settings['ANCHORE_CLI_API_VERSION'] = cli_opts['api-version']

        if cli_opts['insecure']:
            settings['ANCHORE_CLI_SSL_VERIFY'] = "n"

        if cli_opts['json']:
            settings['ANCHORE_CLI_JSON'] = "y"
        
        if cli_opts['debug']:
            settings['ANCHORE_CLI_DEBUG'] = "y"

    except Exception as err:
        raise err

    try:
        if 'ANCHORE_CLI_USER' in settings:
            ret['user'] = settings['ANCHORE_CLI_USER']
        if 'ANCHORE_CLI_PASS' in settings:
            ret['pass'] = settings['ANCHORE_CLI_PASS']
        if 'ANCHORE_CLI_URL' in settings:
            ret['url'] = settings['ANCHORE_CLI_URL']

        if 'ANCHORE_CLI_API_VERSION' in settings:
            ret['api-version'] = settings['ANCHORE_CLI_API_VERSION']
        if 'ANCHORE_CLI_SSL_VERIFY' in settings:
            if settings['ANCHORE_CLI_SSL_VERIFY'].lower() == 'n':
                ret['ssl_verify'] = False
        if 'ANCHORE_CLI_JSON' in settings:
            if settings['ANCHORE_CLI_JSON'].lower() == 'y':
                ret['jsonmode'] = True
        if 'ANCHORE_CLI_DEBUG' in settings:
            if settings['ANCHORE_CLI_DEBUG'].lower() == 'y':
                ret['debug'] = True
    except Exception as err:
        raise err

    return(ret)

def doexit(ecode):
    try:
        sys.stdout.close()
    except:
        pass
    try:
        sys.stderr.close()
    except:
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
    return(ret)

def format_error_output(config, op, params, payload):

    try:
        errdata = json.loads(str(payload))
    except:
        errdata = {'message': str(payload)}

    if config['jsonmode']:
        ret = json.dumps(errdata, indent=4, sort_keys=True)
        return(ret)

    # error message overrides
    #if op == 'image_add':
        #if 'httpcode' in errdata and errdata['httpcode'] == 404:
        #    errdata['message'] = "image cannot be found/fetched from registry"

    obuf = ""
    try:
        outdict = OrderedDict()    
        if 'message' in errdata:
            outdict['Error'] = str(errdata['message'])
        if 'httpcode' in errdata:
            outdict['HTTP Code'] = str(errdata['httpcode'])
        if 'detail' in errdata and errdata['detail']:
            outdict['Detail'] = str(errdata['detail'])

        for k in list(outdict.keys()):
            obuf = obuf + k + ": " + outdict[k] + "\n"
        if not obuf:
            raise Exception("not JSON output could be parsed from error response")
        #obuf = obuf + "\n"
    except Exception as err:
        obuf = str(payload)

    # operation-specific output postfixes
    if op in ['account_delete']:
        if "Invalid account state change requested" in errdata.get('message', ""):
            obuf = obuf + "\nNOTE: accounts must be disabled (anchore-cli account disable <account>) in order to be deleted\n"

    ret = obuf
    return(ret)
            

def format_output(config, op, params, payload):
    if config['jsonmode']:
        try:
            ret = json.dumps(payload, indent=4, sort_keys=True)
        except:
            ret = json.dumps({'payload': str(payload)}, indent=4, sort_keys=True)
        return(ret)


    ret = ""
    try:
        if op == 'image_list':

            if params['show_all']:
                filtered_records = payload
            else:
                # this creates a filtered list w only the latest image records of any found tags
                latest_tag_details = {}
                latest_records = {}
                for image_record in payload:
                    for image_detail in image_record['image_detail']:
                        fulltag = image_detail['fulltag']
                        tagts = dateutil.parser.parse(image_detail['created_at'])
                        if fulltag not in latest_tag_details:
                            latest_tag_details[fulltag] = image_detail
                            latest_records[fulltag] = image_record
                        else:
                            lasttagts = dateutil.parser.parse(latest_tag_details[fulltag]['created_at'])
                            if tagts >= lasttagts:
                                latest_tag_details[fulltag] = image_detail
                                latest_records[fulltag] = image_record

                filtered_records = list(latest_records.values())
                #filtered_records = []
                #for fulltag in latest_records.keys():
                #    filtered_records.append(latest_records[fulltag])

            if params['full']:
                header = ['Full Tag', 'Image ID', 'Analysis Status', 'Image Digest']
            else:
                header = ['Full Tag', 'Image ID', 'Analysis Status']

            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'

            add_rows = []
            for image_record in filtered_records:
                for image_detail_record in image_record['image_detail']:
                    image_detail = copy.deepcopy(image_detail_record)

                    dockerpresent = imageId = fulltag = registy = "None"
                    dockerfile = image_detail.pop('dockerfile', None)
                    if dockerfile:
                        dockerpresent = "Present"

                    imageId = image_detail.pop('imageId', "None") 
                    fulltag = image_detail.pop('registry', "None") + "/" + image_detail.pop('repo', "None") + ":" + image_detail.pop('tag', "None")
                    #registry = image_detail.pop('registry', "None")

                    if params['full']:
                        row = [fulltag, imageId, image_record['analysis_status'], image_record['imageDigest']]
                    else:
                        row = [fulltag, imageId, image_record['analysis_status']]
                    if row not in add_rows:
                        add_rows.append(row)
            for row in add_rows:
                t.add_row(row)
            ret = t.get_string(sortby='Full Tag')
        elif op == 'image_vuln':
            obuf = ""
            if 'query_type' not in params or not params['query_type']:
                outdict = OrderedDict()
                for t in payload:
                    outdict[t] = "available"
                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"
            else:
                if params['query_type'] in ['os', 'non-os', 'all']:
                    header = ['Vulnerability ID', 'Package', 'Severity', 'Fix', 'Vulnerability URL']
                    t = PrettyTable(header)
                    t.set_style(PLAIN_COLUMNS)
                    t.align = 'l'
                    for el in payload['vulnerabilities']:
                        row = [el['vuln'], el['package'], el['severity'], el['fix'], el['url']]
                        t.add_row(row)
                    obuf = obuf + t.get_string(sortby='Severity')
                else:
                    try:
                        if payload['vulnerabilities']:
                            el = payload['vulnerabilities'][0]
                            header = list(el.keys())
                            t = PrettyTable(header)
                            t.set_style(PLAIN_COLUMNS)
                            t.align = 'l'
                            for el in payload['vulnerabilities']:
                                row = []
                                for k in header:
                                    row.append(el[k])
                                t.add_row(row)
                            obuf = obuf + t.get_string()
                        else:
                            raise Exception("no vulnerabilities available for input type ("+str(params['query_type']) + ")")
                    except Exception as err:
                        raise Exception("could not parse content result - exception: " + str(err))

            ret = obuf

        elif op in ['image_content', 'image_metadata']:
            obuf = ""
            if 'query_type' not in params or not params['query_type']:
                outdict = OrderedDict()
                for t in payload:
                    outdict[t] = "available"
                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"
            else:
                if params['query_type'] == 'os':
                    header = ['Package', 'Version', 'License']
                    t = PrettyTable(header)
                    t.set_style(PLAIN_COLUMNS)
                    t.align = 'l'
                    for el in payload['content']:
                        row = [el['package'], el['version'], el['license']]
                        t.add_row(row)
                    obuf = obuf + t.get_string(sortby='Package')
                elif params['query_type'] == 'files':
                    header = ['Filename', 'Size']
                    t = PrettyTable(header)
                    t.set_style(PLAIN_COLUMNS)
                    t.align = 'l'
                    for el in payload['content']:
                        row = [el['filename'], el['size']]
                        t.add_row(row)
                    obuf = obuf + t.get_string(sortby='Size', reversesort=True)
                elif params['query_type'] in ['npm', 'gem', 'python']:
                    header = ['Package', 'Version', 'Location']
                    t = PrettyTable(header)
                    t.set_style(PLAIN_COLUMNS)
                    t.align = 'l'
                    for el in payload['content']:
                        row = [el['package'], el['version'], el['location']]
                        t.add_row(row)
                    obuf = obuf + t.get_string(sortby='Package')
                elif params['query_type'] in ['java']:
                    header = ['Package', 'Specification-Version', 'Implementation-Version', 'Location']
                    t = PrettyTable(header)
                    t.set_style(PLAIN_COLUMNS)
                    t.align = 'l'
                    for el in payload['content']:
                        row = [el['package'], el['specification-version'], el['implementation-version'], el['location']]
                        t.add_row(row)
                    obuf = obuf + t.get_string(sortby='Package')
                elif params['query_type'] in ['manifest', 'dockerfile', 'docker_history']:
                    try:
                        obuf = payload.get('metadata', "").decode('base64')
                    except Exception as err:
                        obuf = ""
                else:
                    try:
                        if payload['content']:
                            el = payload['content'][0]
                            header = list(el.keys())
                            t = PrettyTable(header)
                            t.set_style(PLAIN_COLUMNS)
                            t.align = 'l'
                            for el in payload['content']:
                                row = []
                                for k in header:
                                    row.append(el[k])
                                t.add_row(row)
                            obuf = obuf + t.get_string()
                        else:
                            raise Exception("no content available for input type ("+str(params['query_type']) + ")")
                    except Exception as err:
                        raise Exception("could not parse content result - exception: " + str(err))

            ret = obuf
        elif op in ['image_add', 'image_get', 'image_import']:
            obuf = ""
            for image_record in payload:
                outdict = OrderedDict()

                outdict['Image Digest'] = str(image_record['imageDigest'])
                if image_record.get('parentDigest', None):
                    outdict['Parent Digest'] = str(image_record['parentDigest'])
                outdict['Analysis Status'] = str(image_record['analysis_status'])
                outdict['Image Type'] = str(image_record['image_type'])

                image_detail = copy.deepcopy(image_record['image_detail'][0])
                dockerfile = image_detail.pop('dockerfile', None)

                dockerpresent = "None"
                if dockerfile:
                    dockerpresent = "Present"

                imageId = image_detail.pop('imageId', "None") 
                outdict['Image ID'] = str(imageId)
                #outdict['Dockerfile'] = str(dockerpresent)

                if 'image_content' in image_record and image_record['image_content']:
                    image_content = image_record['image_content']
                    if 'metadata' in image_content and image_content['metadata']:
                        image_content_metadata = image_content['metadata']
                        outdict['Dockerfile Mode'] = str(image_content_metadata['dockerfile_mode'])
                        outdict['Distro'] = str(image_content_metadata['distro'])
                        outdict['Distro Version'] = str(image_content_metadata['distro_version'])
                        outdict['Size'] = str(image_content_metadata['image_size'])
                        outdict['Architecture'] = str(image_content_metadata['arch'])
                        outdict['Layer Count'] = str(image_content_metadata['layer_count'])

                if 'annotations' in image_record and image_record['annotations']:
                    outdict['Annotations'] = ', '.join([str(x)+"="+str(y) for x,y in list(image_record['annotations'].items())])

                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

                for image_detail_record in image_record['image_detail']:
                    image_detail = copy.deepcopy(image_detail_record)
                    outdict = OrderedDict()
                    #outdict['Digest'] = image_detail.pop('fulldigest', "None") 
                    outdict['Full Tag'] = str(image_detail.pop('fulltag', "None"))
                    #outdict['Registry'] = image_detail.pop('registry', "None")

                    for k in list(outdict.keys()):
                        obuf = obuf + k + ": " + outdict[k] + "\n"
                    obuf = obuf + "\n"

            ret = obuf    
        elif op in ['registry_add', 'registry_get', 'registry_update']:
            obuf = ""
            for registry_record in payload:
                outdict = OrderedDict()

                outdict['Registry'] = str(registry_record['registry'])
                outdict['User'] = str(registry_record['registry_user'])
                outdict['Type'] = str(registry_record['registry_type'])
                outdict['Verify TLS'] = str(registry_record['registry_verify'])
                outdict['Created'] = str(registry_record['created_at'])
                outdict['Updated'] = str(registry_record['last_updated'])

                for k in list(outdict.keys()):
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

            ret = obuf
        elif op == 'registry_list':
            header = ['Registry', 'Type', 'User']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'
            for registry_record in payload:
                row = [registry_record['registry'], registry_record['registry_type'], registry_record['registry_user']]
                t.add_row(row)

            ret = t.get_string(sortby='Registry')
        elif op == 'subscription_list':
            header = ['Tag', 'Subscription Type', 'Active']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'
            for subscription_record in payload:
                row = [subscription_record['subscription_key'], subscription_record['subscription_type'], str(subscription_record['active'])]
                t.add_row(row)

            ret = t.get_string(sortby='Tag')
        elif op == 'repo_list':
            header = ['Repository', 'Watched', 'TagCount']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'
            for subscription_record in payload:
                try:
                    sval = json.loads(subscription_record['subscription_value'])
                    tagcount = str(sval['tagcount'])
                except:
                    tagcount = 'N/A'
                row = [subscription_record['subscription_key'], str(subscription_record['active']), str(tagcount)]
                t.add_row(row)

            ret = t.get_string(sortby='Repository')
        elif op in ['repo_get', 'repo_watch', 'repo_unwatch', 'repo_add']:
            header = ['Repository', 'Watched', 'TagCount']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'
            for subscription_record in payload:
                sval = json.loads(subscription_record['subscription_value'])
                try:
                    tagcount = str(sval['tagcount'])
                except:
                    tagcount = 'N/A'
                row = [subscription_record['subscription_key'], str(subscription_record['active']), str(tagcount)]
                t.add_row(row)

            ret = t.get_string(sortby='Repository')

        elif op in ['policy_add', 'policy_get']:
            if 'detail' in params and params['detail']:
                try:
                    ret = json.dumps(payload[0]['policybundle'], indent=4, sort_keys=True)
                except:
                    ret = json.dumps(payload, indent=4, sort_keys=True)
            else:
                obuf = ""

                if op == 'policy_add':
                    payload = [payload]
                else:
                    pass

                for policy_record in payload:
                    outdict = OrderedDict()

                    outdict['Policy ID'] = str(policy_record['policyId'])
                    outdict['Active'] = str(policy_record['active'])
                    outdict['Source'] = str(policy_record['policy_source'])
                    outdict['Created'] = str(policy_record['created_at'])
                    outdict['Updated'] = str(policy_record['last_updated'])

                    for k in list(outdict.keys()):
                        obuf = obuf + k + ": " + outdict[k] + "\n"
                    obuf = obuf + "\n"

                ret = obuf

        elif op == 'policy_list':
            header = ['Policy ID', 'Active', 'Created', 'Updated']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'
            for policy_record in payload:
                row = [policy_record['policyId'], str(policy_record['active']), policy_record['created_at'], policy_record['last_updated']]
                t.add_row(row)

            ret = t.get_string(sortby='Active', reversesort=True)

        elif op == 'evaluate_check':
                obuf = ""

                for eval_record in payload:
                    outdict = OrderedDict()

                    for imageDigest in list(eval_record.keys()):
                        for fulltag in eval_record[imageDigest]:
                            if not eval_record[imageDigest][fulltag]:
                                outdict['Image Digest'] = str(imageDigest)
                                outdict['Full Tag'] = str(fulltag)
                                outdict['Status'] = 'no_eval_available'
                                for k in list(outdict.keys()):
                                    obuf = obuf + k + ": " + outdict[k] + "\n"
                                obuf = obuf + "\n"
                            else:
                                for evaldata in eval_record[imageDigest][fulltag]:
                                    outdict['Image Digest'] = str(imageDigest)
                                    outdict['Full Tag'] = str(fulltag)
                                    if 'detail' in params and params['detail']:
                                        evaldetail = evaldata['detail']
                                        outdict['Image ID'] = str(evaldetail['result']['image_id'])
                                    outdict['Status'] = str(evaldata['status'])
                                    outdict['Last Eval'] = str(evaldata['last_evaluation'])
                                    outdict['Policy ID'] = str(evaldata['policyId'])

                                    t = None
                                    if 'detail' in params and params['detail']:
                                        evaldetail = evaldata['detail']
                                        imageId = evaldetail['result']['image_id']

                                        try:
                                            outdict['Final Action'] = str(evaldetail['result']['final_action'])
                                            outdict['Final Action Reason'] = str(evaldetail['result']['final_action_reason'])
                                        except:
                                            pass

                                        evalresults = evaldetail['result']['result'][imageId]['result']
                                        header = ['Gate', 'Trigger', 'Detail', 'Status']
                                        t = PrettyTable(header)
                                        t.set_style(PLAIN_COLUMNS)
                                        t.align = 'l'
                                        for row in evalresults['rows']:
                                            if 'full' in params and params['full']:
                                                detailrow = row[5]
                                            else:
                                                detailrow = row[5]

                                            status_detail = row[6]
                                            try:
                                                if row[7]:
                                                    eval_whitelist_detail = row[7]
                                                    status_detail = "whitelisted("+eval_whitelist_detail['whitelist_name']+")"
                                            except:
                                                status_detail = row[6]
                                                
                                            newrow = [row[3], row[4], detailrow, status_detail]
                                            t.add_row(newrow)


                                    for k in list(outdict.keys()):
                                        obuf = obuf + k + ": " + outdict[k] + "\n"
                                    if t:
                                        obuf = obuf + "\n"
                                        obuf = obuf + t.get_string() + "\n"

                ret = obuf
        elif op == 'policy_activate':
            try:
                ret = "Success: " + str(params['policyId']) + " activated"
            except:
                ret = 'Success'
        elif op == 'system_status':
            try:
                obuf = ""
                
                outlist = []

                db_version = code_version = None
                for service_record in payload['service_states']:
                    service_status = "N/A"
                    if service_record['status']:
                        service_status = "up"
                    else:
                        service_status = "down ({})".format(service_record['status_message'])
                        
                    outlist.append("Service "+service_record['servicename']+" ("+service_record['hostid']+", " +service_record['base_url'] +"): " + str(service_status))
                    if not db_version:
                        try:
                            db_version = service_record['service_detail']['db_version']
                        except:
                            pass

                    if not code_version:
                        try:
                            code_version = service_record['service_detail']['version']
                        except:
                            pass
                    
                for k in outlist:
                    obuf = obuf + k + "\n"
                obuf = obuf + "\n"

                obuf = obuf + "Engine DB Version: {}\n".format(db_version)
                obuf = obuf + "Engine Code Version: {}\n".format(code_version)

                ret = obuf
            except Exception as err:
                raise err
        elif op == 'event_delete':
            if payload is not None and isinstance(payload, list):
                ret = 'Deleted {} events'.format(len(payload)) if payload else 'No matching events found'
            else:
                ret = 'Success'
        elif op in ['describe_gates']:
            ret = _format_gates(payload, all=params.get('all', False))
        elif op in ['describe_gate_triggers']:
            ret = _format_triggers(payload, params.get('gate', '').lower(), all=params.get('all', False))
        elif op in ['describe_gate_trigger_params']:
            ret = _format_trigger_params(payload, params.get('gate', '').lower(), params.get('trigger', '').lower(), all=params.get('all', False))
        elif op in ['system_feeds_list']:
            try:
                header = ['Feed', 'Group', 'LastSync', 'RecordCount']
                t = PrettyTable(header)
                t.set_style(PLAIN_COLUMNS)
                t.align = 'l'                        
                for el in payload:
                    feed = el.get('name', "N/A")
                    for gel in el['groups']:
                        t.add_row([feed, gel.get('name', "N/A"), gel.get('last_sync', "N/A"), gel.get('record_count', "N/A")])
                ret = t.get_string(sortby='Feed')+"\n"
            except Exception as err:
                raise err
        elif op in ['system_feeds_flush']:
            ret = 'Success'
        elif op == 'event_list':
            header = ['Timestamp', 'Level', 'Service', 'Host', 'Event', 'ID']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'
            for event_res in payload['results']:
                event = event_res['event']
                row = [event['timestamp'], event['level'], event['source']['servicename'], event['source']['hostid'], event['type'], event_res['generated_uuid']]
                t.add_row(row)
            ret = t.get_string()
        elif op == 'event_get':
            ret = yaml.safe_dump(payload['event'], default_flow_style=False)
        elif op == 'query_images_by_vulnerability':
            vulnerability_id = params.get('vulnerability_id')
            #header = ['Severity', 'Full Tag', 'Package', 'Package Type', 'Namespace', 'Digest']
            header = ['Full Tag', 'Severity', 'Package', 'Package Type', 'Namespace', 'Digest']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'            
            for record in payload.get('images', []):
                for tag_record in record.get('image', {}).get('tag_history', []):
                    for package_record in record.get('vulnerable_packages', []):
                        row = [tag_record.get('fulltag', "N/A"), package_record.get('severity', "N/A"), "{}-{}".format(package_record.get("name"), package_record.get("version")), package_record.get("type"), package_record.get('namespace', "N/A"), record.get('image', {}).get('imageDigest', "N/A")]
                        t.add_row(row)
            ret = t.get_string()
        elif op == 'query_images_by_package':
            vulnerability_id = params.get('vulnerability_id')
            header = ['Full Tag', 'Package', 'Package Type', 'Digest']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'            
            for record in payload.get('images', []):
                for tag_record in record.get('image', {}).get('tag_history', []):
                    for package_record in record.get('packages', []):
                        row = [tag_record.get('fulltag', "N/A"), "{}-{}".format(package_record.get("name"), package_record.get("version")), package_record.get("type"), record.get('image', {}).get('imageDigest', "N/A")]
                        t.add_row(row)
            ret = t.get_string()
        elif op == 'account_whoami':
            outdict = OrderedDict()
            
            outdict['Username'] = str(payload.get('user', {}).get('username', "N/A"))
            outdict['AccountName'] = str(payload.get('account', {}).get('name', "N/A"))
            outdict['AccountEmail'] = str(payload.get('account', {}).get('email', "N/A"))
            outdict['AccountType'] = str(payload.get('account', {}).get('type', "N/A"))

            obuf = ""
            for k in list(outdict.keys()):
                obuf = obuf + k + ": " + outdict[k] + "\n"
            obuf = obuf + "\n"

            ret = obuf
        elif op in ['account_add', 'account_get']:
            outdict = OrderedDict()
            
            outdict['Name'] = str(payload.get('name', "N/A"))
            outdict['Email'] = str(payload.get('email', "N/A"))
            outdict['Type'] = str(payload.get('type', "N/A"))
            outdict['State'] = str(payload.get('state', "N/A"))
            outdict['Created'] = str(payload.get('created_at', "N/A"))

            obuf = ""
            for k in list(outdict.keys()):
                obuf = obuf + "{}: {}\n".format(k, outdict[k])
            obuf = obuf + "\n"

            ret = obuf
        elif op in ['account_list']:
            header = ['Name', 'Email', 'Type', 'State', 'Created']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'            
            for record in payload:
                row = [str(record.get('name', "N/A")), str(record.get('email', "N/A")), str(record.get('type', "N/A")), str(record.get('state', "N/A")), str(record.get('created_at', "N/A"))]
                t.add_row(row)
            #ret = t.get_string()
            ret = t.get_string(sortby='Created')+"\n"

        elif op in ['user_add', 'user_get']:
            outdict = OrderedDict()
            
            outdict['Name'] = str(payload.get('username', "N/A"))
            outdict['Created'] = str(payload.get('created_at', "N/A"))

            obuf = ""
            for k in list(outdict.keys()):
                obuf = obuf + "{}: {}\n".format(k, outdict[k])
            obuf = obuf + "\n"

            ret = obuf
        elif op in ['user_list']:
            header = ['Name', 'Created']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'            
            for record in payload:
                row = [str(record.get('username', "N/A")), str(record.get('created_at', "N/A"))]
                t.add_row(row)
            ret = t.get_string(sortby='Created')+"\n"            
        elif op in ['user_setpassword']:
            ret = "Password (re)set success"
        elif op in ['delete_system_service'] or re.match(".*_delete$", op) or re.match(".*_activate$", op) or re.match(".*_deactivate$", op) or re.match(".*_enable$", op) or re.match(".*_disable$", op):
            # NOTE this should always be the last in the if/elif conditional
            ret = 'Success'
        else:
            raise Exception("no output handler for this operation ({})".format(op))
    except Exception as err:
        print("WARNING: failed to format output (returning raw output) - exception: " + str(err))
        try:
            ret = json.dumps(payload, indent=4, sort_keys=True)
        except:
            ret = str(payload)
    return(ret)


def string_splitter(input_str, max_length=40):
    """
    Returns a string that is the input string but with \n inserted every max_length chars

    :param input_str:
    :param max_length: int num of chars between \n
    :return: string
    """

    chunks = []
    chunk = ''
    pieces = input_str.split(' ')

    for piece in pieces:
        if len(chunk) + len(piece) < max_length:
            chunk = ' '.join([chunk, piece])
        else:
            chunks.append(chunk)
            chunk = piece
    chunks.append(chunk)

    return '\n'.join(chunks).strip()


def _format_gates(payload, all=False):
    try:
        if not all:
            header = ['Gate', 'Description']
        else:
            header = ['Gate', 'Description', 'State', 'Superceded By']

        t = PrettyTable(header, hrules=ALL)
        t.align = 'l'

        if payload:
            for gate in payload:
                desc = string_splitter(gate.get('description', ''), 60)
                if all:
                    t.add_row([gate['name'].lower(), desc, gate.get('state', ''), gate.get('superceded_by', '')])
                elif gate.get('state') in [None, 'active']:
                    t.add_row([gate['name'].lower(), desc])

            return t.get_string(sortby='Gate', print_empty=True)
        else:
            return  'No policy spec to parse'

    except Exception as err:
        raise err


def _format_triggers(payload, gate, all=False):
    try:
        if not all:
            header = ['Trigger', 'Description', 'Parameters']
        else:
            header = ['Trigger', 'Description', 'Parameters', 'State', 'Superceded By']
        t = PrettyTable(header, hrules=ALL)
        t.align = 'l'

        if payload:
            for gate in [x for x in payload if x['name'].lower() == gate]:
                for trigger_entry in gate.get('triggers', []):
                    desc = string_splitter(trigger_entry.get('description', ''))
                    param_str = string_splitter(', '.join([x['name'].lower() for x in trigger_entry.get('parameters', [])]), max_length=20)
                    if all:
                        t.add_row([trigger_entry['name'].lower(), desc, param_str, trigger_entry.get('state', ''), trigger_entry.get('superceded_by', '')])
                    elif trigger_entry.get('state') in [None, 'active']:
                        t.add_row([trigger_entry['name'].lower(), desc, param_str])

            return t.get_string(sortby='Trigger', print_empty=True)
        else:
            return 'No policy spec to parse'

    except Exception as err:
        raise err


def _format_trigger_params(payload, gate, trigger, all=False):
    try:
        if all:
            header = ['Parameter', 'Description', 'Required', 'Example', 'State', 'Supereceded By']
        else:
            header = ['Parameter', 'Description', 'Required', 'Example']
        t = PrettyTable(header, hrules=ALL)
        #t.set_style(PLAIN_COLUMNS)
        t.align = 'l'

        if payload:
            for gate in [x for x in payload if x['name'].lower() == gate]:
                for trigger_entry in [x for x in gate.get('triggers', []) if x['name'].lower() == trigger]:
                    for p in trigger_entry.get('parameters', []):
                        desc = string_splitter(p.get('description', ''))
                        if all:
                            t.add_row([p['name'].lower(), desc, p.get('required', True), p.get('example',''), p.get('state', ''), p.get('superceded_by', '')])
                        elif p.get('state') in [None, 'active']:
                            t.add_row([p['name'].lower(), desc, p.get('required', True), p.get('example', '')])


            return t.get_string(sortby='Parameter', print_empty=True)
        else:
            return 'No policy spec to parse'

    except Exception as err:
        raise err

        
def get_eval_ecode(evaldata, imageDigest):
    #0 aid tag 0 status
    ret = 2
    try:
        fulltag = list(evaldata[0][imageDigest].keys())[0]
        status = evaldata[0][imageDigest][fulltag][0]['status'].lower()
        if status == 'pass':
            ret = 0
        elif status == 'fail':
            ret = 1
        else:
            raise Exception("got unknown eval status result: " + str(status))
    except Exception as err:
        ret = 2
    return(ret)

def get_ecode(response):
    ecode = 2
    try:
        httpcode = response['httpcode']
        _logger.debug("fetched httpcode from response: " + str(httpcode))
        if httpcode in range(200, 299):
            ecode = 0
        elif httpcode in [401, 500]:
            ecode = 2
        else:
            ecode = 1
    except:
        pass

    return(ecode)

def check_access(config):
    # test the endpoint
    try:
        rc = anchorecli.clients.apiexternal.get_base_routes(config)
        if not rc['success']:
            raise Exception(json.dumps(rc['error'], sort_keys=True))
    except Exception as err:
        if config['debug']:
            raise Exception("could not access anchore service (user="+str(config['user']) +" url="+str(config['url'])+"): " + str(err))
        else:
            raise Exception("could not access anchore service (user="+str(config['user']) +" url="+str(config['url'])+")")

    return(True)

def discover_inputimage_format(config, input_string):
    itype = None

    if re.match("^sha256:[0-9a-fA-F]{64}", input_string):
        itype = 'imageDigest'
    elif re.match("[0-9a-fA-F]{64}", input_string):
        itype = 'imageid'
    else:
        itype = 'tag'

    return(itype)

def discover_inputimage(config, input_string):
    type = None
    image = None

    patt = re.match(".*(sha256:.*)", input_string)
    if patt:
        urldigest = quote_plus(patt.group(1))
        return("digest", input_string, urldigest)

    try:
        digest = unquote_plus(str(input_string))
        patt = re.match(".*(sha256:.*)", digest)
        if patt:
            return("imageDigest", input_string, input_string)
        patt = re.match(".*(local:.*)", digest)
        if patt:
            return("imageDigest", input_string, input_string)
    except Exception as err:
        pass

    urldigest = None
    ret_type = "tag"
    try:
        ret = anchorecli.clients.apiexternal.get_image(config, tag=input_string)
        if ret['success']:
            urldigest = ret['payload'][0]['imageDigest']
            try:
                image_record = ret['payload'][0]
                for image_detail in image_record['image_detail']:
                    if input_string == image_detail['imageId']:
                        ret_type = "imageid"
                        break
            except Exception as err:
                pass
        else:
            pass
    except Exception as err:
        urldigest = None

    return(ret_type, input_string, urldigest)

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
        registry = 'docker.io'
        digest = instr

    elif len(instr) == 64 and not re.findall("[^0-9a-fA-F]+",instr):
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
            elif a == 'docker.io':
                host = 'docker.io'
                port = None
            elif a in ['localhost', 'localhost.localdomain', 'localbuild']:
                host = a
                port = None
            else:
                patt = re.match(".*\..*", a)
                if patt:
                    host = a
                else:
                    host = 'docker.io'
                    remain = instr
                port = None

        else:
            host = 'docker.io'
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
            registry = ':'.join([host, port])
        else:
            registry = host

        if digest:
            repotag = '@'.join([repo, digest])
        else:
            repotag = ':'.join([repo, tag])

        fulltag = '/'.join([registry, repotag])

        if not digest:
            digest = None
        else:
            fulldigest = registry + '/' + repo + '@' + digest
            tag = None
            fulltag = None
            repotag = None

    ret = {}
    ret['host'] = host
    ret['port'] = port
    ret['repo'] = repo
    ret['tag'] = tag
    ret['registry'] = registry
    ret['repotag'] = repotag
    ret['fulltag'] = fulltag
    ret['digest'] = digest
    ret['fulldigest'] = fulldigest
    ret['imageId'] = imageId

    if ret['fulldigest']:
        ret['pullstring'] = ret['fulldigest']
    elif ret['fulltag']:
        ret['pullstring'] = ret['fulltag']
    else:
        ret['pullstring'] = None

    return(ret)

