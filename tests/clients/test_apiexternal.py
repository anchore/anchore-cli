import pytest
import requests
import responses
from anchorecli.clients import apiexternal

test_config = {
    'user': None,
    'pass': None,
    'url':"http://localhost:8228/v1",
    'ssl_verify':True,
    'jsonmode':False,
    'debug':False,
}

@responses.activate
def test_get_base_routes_succeeds():
    """Test get_base_routes returns succesful"""
    responses.add(responses.GET, test_config['url'], json={}, status=requests.codes.ok)
    resp = apiexternal.get_base_routes(test_config)
    assert resp['httpcode'] == requests.codes.ok
    assert resp['success']

@responses.activate
def test_get_base_routes_fails_unauthorisied():
    """Test get_base_routes handles unauthorised error"""
    responses.add(responses.GET, test_config['url'], body='Unauthorized', status=requests.codes.unauthorized)
    resp = apiexternal.get_base_routes(test_config)
    assert resp['httpcode'] == requests.codes.unauthorized
    assert 'Unauthorized' in resp['error']
    assert not resp['success']

@responses.activate
def test_get_base_routes_fails_connection():
    """Test get_base_routes handles connection errors"""
    responses.add(responses.GET, test_config['url'], body=requests.exceptions.ConnectionError())
    with pytest.raises(requests.exceptions.ConnectionError):
        apiexternal.get_base_routes(test_config)
