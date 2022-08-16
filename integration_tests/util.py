import os
from functools import partial

import pytest
from krs import bootstrap
from krs.token import get_token
from rest_tools.client import RestClient




@pytest.fixture
def keycloak_bootstrap(monkeypatch):
    monkeypatch.setenv('KEYCLOAK_REALM', 'testrealm')
    monkeypatch.setenv('KEYCLOAK_CLIENT_ID', 'testclient')
    monkeypatch.setenv('USERNAME', 'admin')
    monkeypatch.setenv('PASSWORD', 'admin')

    secret = bootstrap.bootstrap()
    monkeypatch.setenv('KEYCLOAK_CLIENT_SECRET', secret)

    # get admin rest client
    token = partial(get_token, os.environ['KEYCLOAK_URL'],
            client_id='testclient',
            client_secret=secret,
    )
    rest_client = RestClient(
        f'{os.environ["KEYCLOAK_URL"]}/auth/admin/realms/testrealm',
        token=token,
        retries=0,
    )

    async def make_client(enable_secret=True):
        client_id = 'http-data-transfer-client'
        # now make http client
        args = {
            'authenticationFlowBindingOverrides': {},
            'bearerOnly': False,
            'clientAuthenticatorType': 'client-secret' if enable_secret else 'public',
            'clientId': client_id,
            'consentRequired': False,
            'defaultClientScopes': [],
            'directAccessGrantsEnabled': False,
            'enabled': True,
            'frontchannelLogout': False,
            'fullScopeAllowed': True,
            'implicitFlowEnabled': False,
            'notBefore': 0,
            'optionalClientScopes': [],
            'protocol': 'openid-connect',
            'publicClient': False,
            'redirectUris': ['http://localhost*'],
            'serviceAccountsEnabled': False,
            'standardFlowEnabled': True,
        }
        await rest_client.request('POST', '/clients', args)
        
        url = f'/clients?clientId={client_id}'
        ret = await rest_client.request('GET', url)
        if not ret:
            raise Exception(f'client does not exist')
        data = ret[0]

        args = {
            'oidc_url': f'{os.environ["KEYCLOAK_URL"]}/auth/realms/testrealm',
            'client_id': client_id,
        }
        if enable_secret:
            url = f'/clients/{data["id"]}/client-secret'
            ret = await rest_client.request('GET', url)
            if 'value' in ret:
                args['client_secret'] = ret['value']
            else:
                raise Exception('no client secret')

        return args

    yield make_client

    tok = bootstrap.get_token()
    bootstrap.delete_service_role('testclient', token=tok)
    bootstrap.delete_realm('testrealm', token=tok)
