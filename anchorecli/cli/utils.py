import json
import re
import sys
import copy
import urllib
import logging
import dateutil.parser
from prettytable import PrettyTable, PLAIN_COLUMNS
from collections import OrderedDict
#from textwrap import fill

import anchorecli.clients.apiexternal

_logger = logging.getLogger(__name__)

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
            errdata['message'] = "image cannot found/fetched from registry"

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
                elif params['query_type'] in ['npm', 'gem']:
                    header = ['Package', 'Version', 'Location']
                    t = PrettyTable(header)
                    t.set_style(PLAIN_COLUMNS)
                    t.align = 'l'
                    for el in payload['content']:
                        row = [el['package'], el['version'], el['location']]
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

                outdict['Image Digest'] = image_record['imageDigest']
                outdict['Analysis Status'] = image_record['analysis_status']
                outdict['Image Type'] = image_record['image_type']

                image_detail = copy.deepcopy(image_record['image_detail'][0])
                dockerfile = image_detail.pop('dockerfile', None)

                dockerpresent = "None"
                if dockerfile:
                    dockerpresent = "Present"

                imageId = image_detail.pop('imageId', "None") 
                outdict['Dockerfile'] = dockerpresent
                outdict['Image ID'] = imageId

                for k in outdict.keys():
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

                for image_detail_record in image_record['image_detail']:
                    image_detail = copy.deepcopy(image_detail_record)
                    outdict = OrderedDict()
                    #outdict['Digest'] = image_detail.pop('fulldigest', "None") 
                    outdict['Full Tag'] = image_detail.pop('fulltag', "None")
                    #outdict['Registry'] = image_detail.pop('registry', "None")

                    for k in outdict.keys():
                        obuf = obuf + k + ": " + outdict[k] + "\n"
                    obuf = obuf + "\n"

            ret = obuf    
        elif op in ['registry_add', 'registry_get', 'registry_update']:
            obuf = ""
            for registry_record in payload:
                outdict = OrderedDict()

                outdict['Registry'] = registry_record['registry']
                outdict['User'] = registry_record['registry_user']
                outdict['Verify TLS'] = str(registry_record['registry_verify'])
                outdict['Created'] = registry_record['created_at']
                outdict['Updated'] = registry_record['last_updated']

                for k in outdict.keys():
                    obuf = obuf + k + ": " + outdict[k] + "\n"
                obuf = obuf + "\n"

            ret = obuf
        elif op == 'registry_list':
            header = ['Registry', 'User']
            t = PrettyTable(header)
            t.set_style(PLAIN_COLUMNS)
            t.align = 'l'
            for registry_record in payload:
                row = [registry_record['registry'], registry_record['registry_user']]
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

                    outdict['Policy ID'] = policy_record['policyId']
                    outdict['Active'] = str(policy_record['active'])
                    outdict['Created'] = policy_record['created_at']
                    outdict['Updated'] = policy_record['last_updated']

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
                                outdict['Image Digest'] = imageDigest
                                outdict['Full Tag'] = fulltag
                                outdict['Status'] = 'no_eval_available'
                                for k in outdict.keys():
                                    obuf = obuf + k + ": " + outdict[k] + "\n"
                                obuf = obuf + "\n"
                            else:
                                for evaldata in eval_record[imageDigest][fulltag]:
                                    outdict['Image Digest'] = imageDigest
                                    outdict['Full Tag'] = fulltag
                                    if 'detail' in params and params['detail']:
                                        evaldetail = evaldata['detail']
                                        outdict['Image ID'] = evaldetail['result']['image_id']
                                    outdict['Status'] = evaldata['status']
                                    outdict['Last Eval'] = evaldata['last_evaluation']
                                    outdict['Policy ID'] = evaldata['policyId']

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

                                            newrow = [row[3], row[4], detailrow, row[6]]
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
                for service_record in payload['detail']['service_states']:
                    service_status = "N/A"
                    if service_record['status']:
                        service_status = "up"
                    else:
                        service_status = "down"

                    outdict["Service "+service_record['servicename']+" ("+service_record['base_url']+")"] = service_status
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


            
        


