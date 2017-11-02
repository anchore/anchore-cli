import os
import re
import sys
import copy
import json
import yaml
import urllib
import logging
import dateutil.parser

from prettytable import PrettyTable, PLAIN_COLUMNS
from collections import OrderedDict
#from textwrap import fill

import anchorecli.clients.apiexternal

_logger = logging.getLogger(__name__)

def setup_config(cli_opts):
    ret = {
        'user':None,
        'pass':None,
        'url':"http://localhost:8228/v1",
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
                    for e in ['ANCHORE_CLI_USER', 'ANCHORE_CLI_PASS', 'ANCHORE_CLI_URL', 'ANCHORE_CLI_SSL_VERIFY']:
                        if e in default_creds:
                            settings[e] = default_creds[e]
                except Exception as err:
                    raise Exception("credentials file exists and has data, but cannot parse: " + str(err))

    except Exception as err:
        raise Exception("error while processing credentials file, please check format and read permissions - exception: " + str(err))
    
    # load environment if present
    try:
        for e in ['ANCHORE_CLI_USER', 'ANCHORE_CLI_PASS', 'ANCHORE_CLI_URL', 'ANCHORE_CLI_SSL_VERIFY', 'ANCHORE_CLI_JSON', 'ANCHORE_CLI_DEBUG']:
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
    for k in gdict.keys():
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
    if op == 'image_add':
        if 'httpcode' in errdata and errdata['httpcode'] == 404:
            errdata['message'] = "image cannot be found/fetched from registry"

    obuf = ""
    try:
        outdict = OrderedDict()    
        if 'message' in errdata:
            outdict['Error'] = str(errdata['message'])
        if 'httpcode' in errdata:
            outdict['HTTP Code'] = str(errdata['httpcode'])
        if 'detail' in errdata and errdata['detail']:
            outdict['Detail'] = str(errdata['detail'])

        for k in outdict.keys():
            obuf = obuf + k + ": " + outdict[k] + "\n"
        #obuf = obuf + "\n"
    except Exception as err:
        obuf = str(payload)

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
                filtered_records = []
                for fulltag in latest_records.keys():
                    filtered_records.append(latest_records[fulltag])

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
                for k in outdict.keys():
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"
            else:
                if params['query_type'] == 'os':
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
                            header = el.keys()
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

        elif op == 'image_content':
            obuf = ""
            if 'query_type' not in params or not params['query_type']:
                outdict = OrderedDict()
                for t in payload:
                    outdict[t] = "available"
                for k in outdict.keys():
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
                else:
                    try:
                        if payload['content']:
                            el = payload['content'][0]
                            header = el.keys()
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

                for k in outdict.keys():
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

                for image_detail_record in image_record['image_detail']:
                    image_detail = copy.deepcopy(image_detail_record)
                    outdict = OrderedDict()
                    #outdict['Digest'] = image_detail.pop('fulldigest', "None") 
                    outdict['Full Tag'] = str(image_detail.pop('fulltag', "None"))
                    #outdict['Registry'] = image_detail.pop('registry', "None")

                    for k in outdict.keys():
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

                for k in outdict.keys():
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

                    for k in outdict.keys():
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

                    for imageDigest in eval_record.keys():
                        for fulltag in eval_record[imageDigest]:
                            if not eval_record[imageDigest][fulltag]:
                                outdict['Image Digest'] = str(imageDigest)
                                outdict['Full Tag'] = str(fulltag)
                                outdict['Status'] = 'no_eval_available'
                                for k in outdict.keys():
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

                                    for k in outdict.keys():
                                        obuf = obuf + k + ": " + outdict[k] + "\n"
                                    obuf = obuf + "\n"

                                    if 'detail' in params and params['detail']:
                                        evaldetail = evaldata['detail']
                                        imageId = evaldetail['result']['image_id']
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
                
                outdict = OrderedDict()
                all_status = "all_up"
                any_up = False
                #for service_record in payload['detail']['service_states']:
                for service_record in payload['service_states']:
                    service_status = "N/A"
                    if service_record['status']:
                        service_status = "up"
                    else:
                        service_status = "down"

                    outdict["Service "+service_record['servicename']+" ("+service_record['base_url']+")"] = str(service_status)
                    if not service_record['status']:
                        all_status = "partial_down"
                    else:
                        any_up = True
                    

                for k in outdict.keys():
                    obuf = obuf + k + ": " + outdict[k] + "\n"

                if not any_up:
                    all_status = "all_down"
                obuf = obuf + "\nEngine Status: " + all_status

                #if 'error_event' in payload['detail'] and payload['detail']['error_event']:
                #    obuf = obuf + "\nError Event Count: " + str(len(payload['detail']['error_event']))

                ret = obuf
            except Exception as err:
                raise err
        elif re.match(".*_delete$", op) or re.match(".*_activate$", op) or re.match(".*_deactivate$", op):
            ret = 'Success'
        elif op in ['prune_candidates', 'pruned_resources']:
            obuf = ""
            try:
                header = ['ResourceType', 'UserId', 'ResourceId', 'Created']
                t = PrettyTable(header)
                t.set_style(PLAIN_COLUMNS)
                t.align = 'l'                        

                if payload[op]:
                    for resource in payload[op]:
                        try:
                            if resource['resourcetype'] == 'archive':
                                idstr = '/'.join([resource['resource_ids']['bucket'], resource['resource_ids']['archiveId']])
                            elif resource['resourcetype'] == 'subscriptions':
                                idstr = '='.join([resource['resource_ids']['subscription_type'], resource['resource_ids']['subscription_key']])
                            elif resource['resourcetype'] == 'evaluations':
                                idstr = resource['resource_ids']['evalId']
                            else:
                                idstr = '/'.join(resource['resource_ids'].values())
                            t.add_row([resource['resourcetype'], resource['userId'], idstr, str(resource['created_at'])])
                        except Exception as err:
                            raise err

                    ret = t.get_string(sortby='ResourceType')+"\n"
                else:
                    if op == 'prune_candidates':
                        ret = "No resources to prune"
                    elif op == 'prune_resources':
                        ret = "No resources were pruned"
                    else:
                        ret = "Nothing to do"
            except Exception as err:
                raise err
            
        else:
            try:
                ret = json.dumps(payload, indent=4, sort_keys=True)
            except:
                ret = str(payload)
    except Exception as err:
        print "WARNING: failed to format output (returning raw output) - exception: " + str(err)
        try:
            ret = json.dumps(payload, indent=4, sort_keys=True)
        except:
            ret = str(payload)
    return(ret)
        
def get_eval_ecode(evaldata, imageDigest):
    #0 aid tag 0 status
    ret = 2
    try:
        fulltag = evaldata[0][imageDigest].keys()[0]
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


def discover_inputimage(config, input_string):
    type = None
    image = None

    patt = re.match(".*(sha256:.*)", input_string)
    if patt:
        urldigest = urllib.quote_plus(patt.group(1))
        return("digest", input_string, urldigest)

    try:
        digest = urllib.unquote_plus(str(input_string))
        patt = re.match(".*(sha256:.*)", digest)
        if patt:
            return("imageDigest", input_string, input_string)
        patt = re.match(".*(local:.*)", digest)
        if patt:
            return("imageDigest", input_string, input_string)
    except Exception as err:
        pass

    urldigest = None
    try:
        ret = anchorecli.clients.apiexternal.get_image(config, tag=input_string)
        if ret['success']:
            urldigest = ret['payload'][0]['imageDigest']
        else:
            pass
    except Exception as err:
        urldigest = None

    return("tag", input_string, urldigest)


            
        


