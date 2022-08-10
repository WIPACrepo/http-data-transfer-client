import json
import jwt
import pytest
import time
from rest_tools.utils.auth import Auth

from http_data_transfer_client import app, aioclient

from .util import gen_keys, gen_keys_bytes, fake_server


@pytest.fixture
def conf_file(mocker, tmp_path):
    filename = tmp_path / 'conf'
    mock = mocker.patch('http_data_transfer_client.app._conf_file', return_value=filename)
    yield filename


def test_store_tokens(conf_file, gen_keys_bytes):
    a = Auth(gen_keys_bytes[0], pub_secret=gen_keys_bytes[1], algorithm='RS256')
    access = a.create_token('sub', expiration=20)

    app.store_tokens(access)
    with open(conf_file) as f:
        data = json.load(f)
    assert data['access_token'] == access
    assert not data.get('refresh_token', None)

    refresh = a.create_token('sub', expiration=20)
    app.store_tokens(access, refresh)
    with open(conf_file) as f:
        data = json.load(f)
    assert data['access_token'] == access
    assert data['refresh_token'] == refresh


def test_load_tokens(conf_file, gen_keys_bytes):
    a = Auth(gen_keys_bytes[0], pub_secret=gen_keys_bytes[1], algorithm='RS256')
    access = a.create_token('sub', expiration=20)

    app.store_tokens(access)
    access_token, refresh_token = app.load_tokens()
    assert access_token == access
    assert refresh_token == None

    refresh = a.create_token('sub', expiration=20)
    app.store_tokens(access, refresh)
    access_token, refresh_token = app.load_tokens()
    assert access_token == access
    assert refresh_token == refresh


def test_load_tokens_expired(conf_file, gen_keys_bytes):
    a = Auth(gen_keys_bytes[0], pub_secret=gen_keys_bytes[1], algorithm='RS256')
    access = jwt.encode({'iat': time.time(), 'sub': 'sub', 'exp': time.time()-10}, gen_keys_bytes[0], algorithm='RS256')

    app.store_tokens(access)
    access_token, refresh_token = app.load_tokens()
    assert access_token == None
    assert refresh_token == None

    refresh = jwt.encode({'iat': time.time(), 'sub': 'sub'}, gen_keys_bytes[0], algorithm='RS256')
    app.store_tokens(access, refresh)
    access_token, refresh_token = app.load_tokens()
    assert access_token == None
    assert refresh_token == refresh


def test_get_rest_url_single_source():
    source = ['https://foo.bar/baz']
    dest = '/baz'
    ret = app.get_rest_url(source, dest)
    assert ret == 'https://foo.bar'


def test_get_rest_url_multi_source():
    source = ['https://foo.bar/baz', 'https://foo.bar/foo']
    dest = '/baz'
    ret = app.get_rest_url(source, dest)
    assert ret == 'https://foo.bar'


def test_get_rest_url_dest():
    source = ['/baz']
    dest = 'https://foo.bar/baz'
    ret = app.get_rest_url(source, dest)
    assert ret == 'https://foo.bar'


def test_get_rest_url_both():
    source = ['https://foo.bar/baz']
    dest = 'https://foo.bar/baz'
    with pytest.raises(RuntimeError):
        app.get_rest_url(source, dest)


def test_get_rest_url_none():
    source = ['/foo']
    dest = '/baz'
    with pytest.raises(RuntimeError):
        app.get_rest_url(source, dest)


def test_get_rest_url_only_some():
    source = ['https://foo.bar/baz', '/foo']
    dest = '/baz'
    with pytest.raises(RuntimeError):
        app.get_rest_url(source, dest)


def test_get_rest_url_multi_mixed_source():
    source = ['https://foo.bar/baz', 'https://bar.foo/foo']
    dest = '/baz'
    with pytest.raises(RuntimeError):
        app.get_rest_url(source, dest)


def test_get_rest_url_http():
    source = ['http://foo.bar/baz']
    dest = '/baz'
    ret = app.get_rest_url(source, dest)
    assert ret == 'http://foo.bar'


async def test_do_transfer_get(fake_server, tmp_path):
    test_data = b'thefakedata'
    def reader():
        return test_data
    address, server = fake_server(reader, None)

    source = [f'{address}/baz']
    dest = tmp_path / 'dest'

    async with aioclient.AIOClient(address) as rc:
        await app.do_transfer(source, str(dest), rest_client=rc)

    assert dest.is_file()
    with open(dest, 'rb') as f:
        assert test_data == f.read()


async def test_do_transfer_get_multi(fake_server, tmp_path):
    test_data = b'thefakedata'
    def reader():
        return test_data
    address, server = fake_server(reader, None)

    source = [f'{address}/foo', f'{address}/bar']
    dest = tmp_path / 'dest'
    dest.mkdir()

    async with aioclient.AIOClient(address) as rc:
        await app.do_transfer(source, f'{dest}/', rest_client=rc)

    dests = [dest / 'foo', dest / 'bar']
    for d in dests:
        assert d.is_file()
        with open(d, 'rb') as f:
            assert test_data == f.read()


async def test_do_transfer_put(fake_server, tmp_path):
    test_data = b'thefakedata'
    def writer(data):
        writer.data += data
    writer.data = b''
    address, server = fake_server(None, writer)

    source = [str(tmp_path / 'source')]
    dest = f'{address}/dest'

    with open(source[0], 'wb') as f:
        f.write(test_data)

    async with aioclient.AIOClient(address) as rc:
        await app.do_transfer(source, dest, rest_client=rc)

    assert writer.data == test_data


async def test_do_transfer_put_multi(fake_server, tmp_path):
    test_data = b'thefakedata'
    def writer(data):
        writer.data += data
    writer.data = b''
    address, server = fake_server(None, writer)

    source = [str(tmp_path / 'source'), str(tmp_path / 'source2')]
    dest = f'{address}/dest/'

    for s in source:
        with open(s, 'wb') as f:
            f.write(test_data)

    async with aioclient.AIOClient(address) as rc:
        await app.do_transfer(source, dest, rest_client=rc)

    assert writer.data == test_data * 2