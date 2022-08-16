from urllib.parse import urlparse, quote
import os
import logging
import pytest
import aiohttp
from unittest.mock import AsyncMock

from http_data_transfer_client import server

from .util import keycloak_bootstrap


logger = logging.getLogger('test_oauth')


async def test_server_redirect_login(keycloak_bootstrap):
    kwargs = await keycloak_bootstrap(enable_secret=False)

    state = {}
    s, address = server.create_server(state, **kwargs)
    if not address.endswith('/'):
        address += '/'

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(address, allow_redirects=False) as resp:
                assert resp.status == 302
                logger.info('Location header: %r', resp.headers['Location'])
                assert resp.headers['Location'] == address+'login?next='+quote(address, safe='')
    finally:
        await s.stop()

async def test_server_redirect_keycloak(keycloak_bootstrap):
    kwargs = await keycloak_bootstrap(enable_secret=False)

    state = {}
    s, address = server.create_server(state, **kwargs)
    if not address.endswith('/'):
        address += '/'

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(address, allow_redirects=False) as resp:
                redirect_url = resp.headers['Location']
            async with session.get(redirect_url, allow_redirects=False) as resp:
                assert resp.status == 302
                o = urlparse(resp.headers['Location'])
                logger.info('Location header: %r', resp.headers['Location'])
                assert o.scheme + '://' + o.netloc == os.environ['KEYCLOAK_URL']
                assert o.path == '/auth/realms/testrealm/protocol/openid-connect/auth'
                query = dict(p.split('=',1) for p in o.query.split('&'))
                assert query.get('response_type', '') == 'code'
                assert query.get('redirect_uri', '') == quote(address+'login', safe='')
                assert query.get('client_id', '') == kwargs['client_id']
                assert 'client_secret' not in query
                assert query.get('scope', '') == 'posix'
    finally:
        await s.stop()

async def test_server_redirect_keycloak_secret(keycloak_bootstrap):
    kwargs = await keycloak_bootstrap(enable_secret=True)
    logger.info('create_server kwargs: %r', kwargs)

    state = {}
    s, address = server.create_server(state, **kwargs)
    if not address.endswith('/'):
        address += '/'

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(address, allow_redirects=False) as resp:
                redirect_url = resp.headers['Location']
            async with session.get(redirect_url, allow_redirects=False) as resp:
                assert resp.status == 302
                logger.info('Location header: %r', resp.headers['Location'])
                o = urlparse(resp.headers['Location'])
                assert o.scheme + '://' + o.netloc == os.environ['KEYCLOAK_URL']
                assert o.path == '/auth/realms/testrealm/protocol/openid-connect/auth'
                query = dict(p.split('=',1) for p in o.query.split('&'))
                assert query.get('response_type', '') == 'code'
                assert query.get('redirect_uri', '') == quote(address+'login', safe='')
                assert query.get('client_id', '') == kwargs['client_id']
                assert query.get('scope', '') == 'posix+offline_access'
    finally:
        await s.stop()

async def test_token_server(keycloak_bootstrap, mocker):
    kwargs = await keycloak_bootstrap(enable_secret=False)

    class Server:
        async def stop(self):
            pass

    s = AsyncMock(Server)
    def foo(state, *args, **kwargs):
        state['access_token'] = 'access'
        return s, 'address'

    mocker.patch('http_data_transfer_client.server.create_server', side_effect=foo)

    access_token, refresh_token = await server.token_server(browser=False, **kwargs)

    assert access_token == 'access'
    assert refresh_token == None

    s.stop.assert_awaited()

async def test_token_server_bytes(keycloak_bootstrap, mocker):
    kwargs = await keycloak_bootstrap(enable_secret=True)

    class Server:
        async def stop(self):
            pass

    s = AsyncMock(Server)
    def foo(state, *args, **kwargs):
        state['access_token'] = b'access'
        state['refresh_token'] = b'refresh'
        return s, 'address'

    mocker.patch('http_data_transfer_client.server.create_server', side_effect=foo)

    access_token, refresh_token = await server.token_server(browser=False, **kwargs)

    assert access_token == 'access'
    assert refresh_token == 'refresh'

    s.stop.assert_awaited()
