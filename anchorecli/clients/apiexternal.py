import json
import re
import requests
import hashlib
import logging
import urllib3
import requests.packages.urllib3
try:
    from urllib.parse import urlparse, urlunparse, urlencode
except:
    from urllib import urlencode
    from urlparse import urlparse,urlunparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
def system_feeds_list(config):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "system/feeds"])

    try:
        _logger.debug("GET url="+str(url))
        _logger.debug("GET insecure="+str(config['ssl_verify']))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def system_feeds_sync(config, flush=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "system/feeds?flush={}".format(flush)])

    try:
        _logger.debug("POST url="+str(url))
        _logger.debug("POST insecure="+str(config['ssl_verify']))
        r = requests.post(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)    

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

def delete_system_service(config, host_id, servicename):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    if not host_id or not servicename:
        raise Exception("invalid host_id or servicename given")

    ret = {}    

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "system", "services", servicename, host_id])

    try:
        _logger.debug("DELETE url="+str(url))
        r = requests.delete(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# image clients

def add_image(config, tag=None, digest=None, dockerfile=None, force=False, annotations={}, autosubscribe=True):
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

    if annotations:
        payload['annotations'] = annotations

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "images"])

    url = url + "?autosubscribe="+str(autosubscribe)
    if force:
        url = url + "&force=true"

    try:
        _logger.debug("POST url="+str(url))
        r = requests.post(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def detect_api_version(config):
    """
    Returns the api version for the service as a tuple of ints. E.g '0.1.1' -> (0, 1, 1)
    :param config:
    :return: tuple of ints
    """
    if config['api-version']:
        return tuple([int(x) for x in config['api-version'].split('.')])

    userId = config['user']
    password = config['pass']

    # contruct candidate URLs for finding the anchore-engine swagger.json document, supporting indirection through proxies and base anchore-engine service
    urls = []
    try:
        url = urlparse(config['url'])
        url = urlunparse((url.scheme, url.netloc, '/swagger.json', url.params, url.query, url.fragment))
        urls.append(url)
    except:
        pass

    try:
        url = '/'.join([re.sub("/$", "", config['url']), "swagger.json"])
        urls.append(url)
    except:
        pass

    for url in urls:
        # Detect if we can use query params or must use the GET body
        version = None
        try:
            resp = requests.get(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
            if not resp or not resp.json().get('info').get('version'):
                pass
            else:
                version = tuple([int(x) for x in resp.json().get('info').get('version').split('.')])
        except:
            pass

        if version:
            return(version)

    return(tuple([0]))

def get_image(config, tag=None, image_id=None, imageDigest=None, history=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']
    api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "images"])

    if imageDigest:
        url += '/{}'.format(imageDigest)
    elif image_id:
        url += '/by_id/{}'.format(image_id)
    elif tag:
        params['fulltag'] = tag
    else:
        return(False)

    if history:
        params['history'] = 'true'
    else:
        params['history'] = 'false'


    if api_version < api_version_query_support and tag:
        payload = {'tag': params.pop('fulltag')}
    else:
        payload = None

    try:
        _logger.debug("GET url="+str(url))
        _logger.debug("GET params="+str(params))
        _logger.debug("Use get body because detected api version {} < {}? {}".format(api_version, api_version_query_support, (payload is not None)))
        _logger.debug("GET insecure="+str(config['ssl_verify']))
        if payload:
            r = requests.get(url, data=json.dumps(payload), params=params, auth=(userId, password), verify=config['ssl_verify'],
                             headers=header_overrides)
        else:

            r = requests.get(url, params=params, auth=(userId, password), verify=config['ssl_verify'],
                             headers=header_overrides)

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

def query_image(config, imageDigest=None, query_group=None, query_type=None, vendor_only=True):
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

    if query_group == 'vuln':
        url = url + "?vendor_only={}".format(vendor_only)

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

def check_eval(config, imageDigest=None, history=False, detail=False, tag=None, policyId=None):
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

    if policyId:
        url = url + "&policyId="+str(policyId)

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

    hashstr = '+'.join([userId, subscription_key, subscription_type]).encode('utf-8')
    #subscription_id = hashlib.md5('+'.join([userId, subscription_key, subscription_type])).hexdigest()
    subscription_id = hashlib.md5(hashstr).hexdigest()

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

    hashstr = '+'.join([userId, subscription_key, subscription_type]).encode('utf-8')
    #subscription_id = hashlib.md5('+'.join([userId, subscription_key, subscription_type])).hexdigest()
    subscription_id = hashlib.md5(hashstr).hexdigest()

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

def add_subscription(config, subscription_type, subscription_key, active=True):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "subscriptions"])

    payload = {'active':active, 'subscription_key': subscription_key, 'subscription_type': subscription_type}
    try:
        _logger.debug("POST url="+str(url))
        r = requests.post(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def delete_subscription(config, subscription_type=None, subscription_key=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    hashstr = '+'.join([userId, subscription_key, subscription_type]).encode('utf-8')
    #subscription_id = hashlib.md5('+'.join([userId, subscription_key, subscription_type])).hexdigest()
    subscription_id = hashlib.md5(hashstr).hexdigest()

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "subscriptions", subscription_id])

    try:
        _logger.debug("DELETE url="+str(url))
        r = requests.delete(url, auth=(userId, password), verify=config['ssl_verify'])
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
    if subscription_key or subscription_type:
        url = url + "?"
        if subscription_key:
            url = url + "subscription_key="+subscription_key+"&"
        if subscription_type:
            url = url + "subscription_type="+subscription_type+"&"

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

# repo clients

def add_repo(config, input_repo, autosubscribe=False, lookuptag=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "repositories?repository="+input_repo+"&autosubscribe="+str(autosubscribe)])
    if lookuptag:
        url = url + "&lookuptag="+str(lookuptag)

    try:
        _logger.debug("POST url="+str(url))
        r = requests.post(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)
    #return(add_subscription(config, 'repo_update', input_repo))

def get_repo(config, input_repo=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    filtered_records = []
    subscriptions = get_subscription(config, subscription_type='repo_update')
    subscription_records = subscriptions['payload']
    for i in range(0, len(subscription_records)):
        subscription_record = subscription_records[i]
        if subscription_record['subscription_type'] == 'repo_update':
            if not input_repo or subscription_record['subscription_key'] == input_repo:
                filtered_records.append(subscription_record)

    subscriptions['payload'] = filtered_records

    return(subscriptions)

def delete_repo(config, input_repo, force=False):
    return(delete_subscription(config, 'repo_update', input_repo))

def watch_repo(config, input_repo):
    return(activate_subscription(config, 'repo_update', input_repo))

def unwatch_repo(config, input_repo):
    return(deactivate_subscription(config, 'repo_update', input_repo))

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


def add_registry(config, registry=None, registry_user=None, registry_pass=None, registry_type=None, insecure=False, validate=True):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "registries"])
    url = "{}?validate={}".format(url, validate)

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

def update_registry(config, registry=None, registry_user=None, registry_pass=None, registry_type=None, insecure=False, validate=True):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "registries", registry])
    url = "{}?validate={}".format(url, validate)

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

def describe_policy_spec(config):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub('/$','', base_url)
    url = '/'.join([base_url, 'system', 'policy_spec'])
    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def list_events(config, since=None, before=None, level=None, service=None, host=None, resource=None, all=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "events"])

    if since:
        params['since'] = since

    if before:
        params['before'] = before

    if level:
        params['level'] = level

    if service:
        params['source_servicename'] = service

    if host:
        params['source_hostid'] = host

    if resource:
        params['resource_id'] = resource

    try:
        if all:
            # Results might be paginated here, so loop
            events = []
            while True:
                if ret and ret['payload']['next_page'] is True:
                    params['page'] = int(ret['payload']['page']) + 1

                _logger.debug("GET url=" + str(url))
                _logger.debug("GET params=" + str(params))
                _logger.debug("GET insecure=" + str(config['ssl_verify']))

                r = requests.get(url, params=params, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
                ret = anchorecli.clients.common.make_client_result(r, raw=False)

                if ret['success']:
                    events += ret['payload']['results']
                    ret['payload']['results'] = events
                else:
                    break

                if ret['payload']['next_page'] is False:
                    break
        else:
            _logger.debug("GET url=" + str(url))
            _logger.debug("GET params=" + str(params))
            _logger.debug("GET insecure=" + str(config['ssl_verify']))

            r = requests.get(url, params=params, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
            ret = anchorecli.clients.common.make_client_result(r, raw=False)

    except Exception as err:
        raise err

    return(ret)


def get_event(config, event_id):
    userId = config['user']
    password = config['pass']
    base_url = config['url']
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "events", event_id])

    try:
        _logger.debug("GET url="+str(url))
        _logger.debug("GET insecure="+str(config['ssl_verify']))

        r = requests.get(url, params=params, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def delete_events(config, since=None, before=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "events"])

    if since:
        params['since'] = since

    if before:
        params['before'] = before

    try:
        _logger.debug("DELETE url="+str(url))
        _logger.debug("DELETE params="+str(params))
        _logger.debug("DELETE insecure="+str(config['ssl_verify']))

        r = requests.delete(url, params=params, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def delete_event(config, event_id):
    userId = config['user']
    password = config['pass']
    base_url = config['url']
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "events", event_id])

    try:
        _logger.debug("DELETE url="+str(url))
        _logger.debug("DELETE insecure="+str(config['ssl_verify']))

        r = requests.delete(url, params=params, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def query_images_by_vulnerability(config, vulnerability_id, namespace=None, affected_package=None, severity=None, vendor_only=True):
    userId = config['user']
    password = config['pass']
    base_url = config['url']
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "query/images/by_vulnerability?vulnerability_id={}".format(vulnerability_id)])

    query_params = {}
    if namespace:
        query_params['namespace'] = namespace
    if affected_package:
        query_params['affected_package'] = affected_package
    if severity:
        query_params['severity'] = severity
    if vendor_only:
        query_params['vendor_only'] = vendor_only
    
    if query_params:
        url = "{}&{}".format(url, urlencode(query_params))

    try:
        _logger.debug("GET url="+str(url))
        _logger.debug("GET insecure="+str(config['ssl_verify']))

        r = requests.get(url, params=params, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def query_images_by_package(config, name, version=None, package_type=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']
    # api_version_query_support = (0, 1, 6)

    ret = {}
    params = {}
    # api_version = detect_api_version(config)

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "query/images/by_package?name={}".format(name)])

    query_params = {}
    if version:
        query_params['version'] = version
    if package_type:
        query_params['package_type'] = package_type
    
    if query_params:
        url = "{}&{}".format(url, urlencode(query_params))

    try:
        _logger.debug("GET url="+str(url))
        _logger.debug("GET insecure="+str(config['ssl_verify']))

        r = requests.get(url, params=params, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# account clients

def add_account(config, account_name=None, email=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "accounts"])

    payload = {}

    payload.update({'name': account_name})
    if email:
        payload['email'] = email

    try:
        _logger.debug("POST url="+str(url))
        r = requests.post(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def get_account(config, account_name=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)

    if account_name:
        url = '/'.join([base_url, "accounts", account_name])
    else:
        url = '/'.join([base_url, "account"])

    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def list_accounts(config):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "accounts"])

    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def del_account(config, account_name=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "accounts", account_name])

    try:
        _logger.debug("DELETE url="+str(url))
        r = requests.delete(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def enable_account(config, account_name=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "accounts", account_name, 'state'])

    payload = {}
    payload.update({'state': 'enabled'})

    try:
        _logger.debug("PUT url="+str(url))
        r = requests.put(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def disable_account(config, account_name=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "accounts", account_name, 'state'])

    payload = {}
    payload.update({'state': 'disabled'})

    try:
        _logger.debug("PUT url="+str(url))
        r = requests.put(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

# user clients

def add_user(config, account_name=None, user_name=None, user_password=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "accounts", account_name, 'users'])

    payload = {}
    payload.update({'username': user_name, 'password': user_password})

    try:
        _logger.debug("POST url="+str(url))
        r = requests.post(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def get_user(config, account_name=None, user_name=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    if account_name and user_name:
        url = '/'.join([base_url, "accounts", account_name, 'users', user_name])
    elif not account_name and not user_name:
        url = '/'.join([base_url, "user"])
    else:
        return(ret)

    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def del_user(config, account_name=None, user_name=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "accounts", account_name, 'users', user_name])

    try:
        _logger.debug("DELETE url="+str(url))
        r = requests.delete(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)


def list_users(config, account_name=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    if account_name:
        url = '/'.join([base_url, "accounts", account_name, 'users'])

    try:
        _logger.debug("GET url="+str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)

def update_user_password(config, account_name=None, user_name=None, user_password=None):
    userId = config['user']
    password = config['pass']
    base_url = config['url']

    ret = {}

    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "accounts", account_name, 'users', user_name, 'credentials'])

    payload = {}
    payload.update({'type': 'password', 'value': user_password})

    try:
        _logger.debug("POST url="+str(url))
        r = requests.post(url, data=json.dumps(payload), auth=(userId, password), verify=config['ssl_verify'], headers=header_overrides)
        ret = anchorecli.clients.common.make_client_result(r, raw=False)
    except Exception as err:
        raise err

    return(ret)        
        
