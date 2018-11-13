import json
import re
import os


def make_client_result(response, raw=False):
    ret = {
        'success':False,
        'httpcode':0,
        'payload':{},
        'error':{}
    }

    try:
        ret['httpcode'] = response.status_code

        if response.status_code in range(200, 299):
            ret['success'] = True
            if raw == True:
                ret['payload'] = response.text
            else:
                try:
                    ret['payload'] = json.loads(response.text)
                except:
                    ret['payload'] = response.text

        else:
            ret['success'] = False

            if raw == True:
                ret['error'] = response.text
            else:
                try:
                    ret['error'] = json.loads(response.text)
                except:
                    ret['error'] = response.text

            if not ret.get('error', None) and response.status_code in [401]:
                ret['error'] = "Unauthorized - please check your username/password"
    except Exception as err:
        raise err

    return(ret)
