import json
import re
import os
import sys
import requests
import hashlib
import logging
import urllib3
import requests.packages.urllib3
#from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#urllib.disable_warnings(urllib.exceptions.InsecureRequestWarning)

import anchorecli.clients.common

_logger = logging.getLogger(__name__)

header_overrides = {'Content-Type': 'application/json'}

def get_base_routes(config):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    try:
        r = requests.get(base_url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# system clients

def system_status(config):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "system"])

    try:
        _logger.debug("GET url="+str(url))
        _logger.debug("GET insecure="+str(config['ssl_verify']))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# image clients

def add_image(config, tag=None, digest=None, dockerfile=None, force=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    payload = {}
    if dockerfile:
        payload['dockerfile'] = dockerfile

    if digest:
        payload['digest'] = digest
    elif tag:
        payload['tag'] = tag
    else:
        return(False)

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "images"])

    if force:
        url = url + "?force=true"

    try:
        _logger.debug("POST url="+str(url))
        r = requests.post(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def get_image(config, tag=None, digest=None, imageDigest=None, history=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    payload = {}
    if imageDigest:
        payload['imageDigest'] = imageDigest
    elif digest:
        payload['digest'] = digest
    elif tag:
        payload['tag'] = tag
    else:
        return(False)

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "images"])

    if history:
        url = url + "?history=true"
    else:
        url = url + "?history=false"
    
    try:
        _logger.debug("GET url="+str(url))
        _logger.debug("GET payload="+json.dumps(payload))
        _logger.debug("GET insecure="+str(config['ssl_verify']))
        r = requests.get(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def get_images(config):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    _logger.info("Base = " + base_url)
    url = '/'.join([base_url, "images"])
    _logger.info("Url = " + url)
    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def import_image(config, anchore_data=[]):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = []

    payload = anchore_data[0]
    
    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "imageimport"])

    try:
        _logger.debug("POST url="+str(url))

        r = requests.post(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def query_image(config, imageDigest=None, query_group=None, query_type=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "images", imageDigest])
    
    if query_group:
        url = '/'.join([url, query_group])
    else:
        raise Exception("need to specify a query group")

    if query_type:
        url = '/'.join([url, query_type])
    
    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def delete_image(config, imageDigest=None, force=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    if not imageDigest:
        raise Exception("must specify a valid imageDigest to delete")

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "images", imageDigest])

    if force:
        url = url+"?force=True"

    try:
        _logger.debug("DELETE url="+str(url))
        r = requests.delete(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# policy clients

def add_policy(config, policybundle={}, detail=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    payload = policybundle

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "policies"])

    if detail:
        url = url + "?detail=True"
    else:
        url = url + "?detail=False"

    try:
        _logger.debug("POST url="+str(url))
        r = requests.post(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def get_policy(config, policyId=None, detail=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    if policyId:
        url = '/'.join([base_url, "policies", policyId])
    else:
        return(False)

    if detail:
        url = url + "?detail=True"
    else:
        url = url + "?detail=False"

    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
        
    except Exception as err:
        raise err

    return(ret)

def get_policies(config, detail=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "policies"])

    if detail:
        url = url + "?detail=True"
    else:
        url = url + "?detail=False"

    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def update_policy(config, policyId, policy_record={}):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "policies", policyId])

    payload = policy_record

    try:
        _logger.debug("PUT url="+str(url))
        r = requests.put(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def delete_policy(config, policyId):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "policies", policyId])

    try:
        _logger.debug("DELETE url="+str(url))
        r = requests.delete(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# eval clients

def check_eval(config, imageDigest=None, history=False, detail=False, tag=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "images", imageDigest, "check"])
    if history:
        url = url + "?history=true"
    else:
        url = url + "?history=false"
    if detail:
        url = url + "&detail=true"
    else:
        url = url + "&detail=false"

    if tag:
        url = url + "&tag="+str(tag)

    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# subscription clients

def activate_subscription(config, subscription_type, subscription_key):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    subscription_id = hashlib.md5('+'.join([userId, subscription_key, subscription_type])).hexdigest()

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "subscriptions", subscription_id])
    
    payload = {'active':True, 'subscription_key': subscription_key, 'subscription_type': subscription_type}
    try:
        _logger.debug("PUT url="+str(url))
        r = requests.put(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def deactivate_subscription(config, subscription_type, subscription_key):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    subscription_id = hashlib.md5('+'.join([userId, subscription_key, subscription_type])).hexdigest()

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "subscriptions", subscription_id])

    payload = {'active':False, 'subscription_key': subscription_key, 'subscription_type': subscription_type}
    try:
        _logger.debug("PUT url="+str(url))
        r = requests.put(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def get_subscription(config, subscription_type=None, subscription_key=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "subscriptions"])
    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def get_subscription_types(config):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "subscriptions", "types"])
    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# interactive clients

def interactive_query(config, payload={}):
    return(interactive(config, "query", payload=payload))

def interactive_analyze(config, payload={}):
    return(interactive(config, "analyze", payload=payload))

def interactive_evaluate(config, payload={}):
    return(interactive(config, "evaluate", payload=payload))

def interactive(config, op_type, payload={}):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "interactive", op_type])
    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# registry clients

def get_registry(config, registry=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "registries"])
    if registry:
        url = '/'.join([url, registry])

    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def add_registry(config, registry=None, registry_user=None, registry_pass=None, registry_type=None, insecure=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "registries"])

    payload = {}
    verify = not insecure
    payload.update({'registry': registry, 'registry_user': registry_user, 'registry_pass': registry_pass, 'registry_type': registry_type, 'registry_verify':verify})

    try:
        _logger.debug("POST url="+str(url))
        r = requests.post(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def update_registry(config, registry=None, registry_user=None, registry_pass=None, registry_type=None, insecure=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "registries", registry])

    payload = {}
    verify = not insecure
    payload.update({'registry': registry, 'registry_user': registry_user, 'registry_pass': registry_pass, 'registry_type': registry_type, 'registry_verify':verify})

    try:
        _logger.debug("PUT url="+str(url))
        r = requests.put(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def delete_registry(config, registry=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "registries", registry])
    
    try:
        _logger.debug("DELETE url="+str(url))
        r = requests.delete(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# prune interface

def get_prune_resourcetypes(config):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "system", "prune"])
    
    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def get_prune_candidates(config, resourcetype, dangling=True, olderthan=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "system", "prune", resourcetype + '?dangling='+str(dangling)])
    if olderthan:
        url = url + "&olderthan="+str(int(olderthan))
    
    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def perform_prune(config, resourcetype, prune_candidates):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "system", "prune", resourcetype])
    
    payload = json.dumps(prune_candidates)
    
    try:
        _logger.debug("POST url="+str(url))
        _logger.debug("POST payload="+str(payload))
        r = requests.post(url, data=payload, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)
