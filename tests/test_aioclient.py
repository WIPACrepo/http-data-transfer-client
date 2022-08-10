from tempfile import NamedTemporaryFile
import pytest

from http_data_transfer_client import aioclient

from .util import fake_server


async def test_aioclient_context():
    client = aioclient.AIOClient(
        address='address',
        chunk_size=1234,
        range_size=5678,
    )

    async with client as c:
        pass


async def test_aioclient_read_iter(fake_server):
    test_data = b'thefakedata'
    def reader():
        return test_data
    address, server = fake_server(reader, None)

    client = aioclient.AIOClient(
        address=address,
        chunk_size=1234,
        range_size=5678,
    )

    data = b''
    async with client as c:
        async for chunk in c.read_iter('/'):
            data += chunk

    assert data == test_data


async def test_aioclient_read_to_file(fake_server):
    test_data = b'thefakedata'
    def reader():
        return test_data
    address, server = fake_server(reader, None)

    client = aioclient.AIOClient(
        address=address,
        chunk_size=1234,
        range_size=5678,
    )

    data = b''
    with NamedTemporaryFile() as f:
        async with client as c:
            await c.read_to_file('/', f.name)
        f.seek(0)
        data = f.read()

    assert data == test_data


async def test_aioclient_read_to_file_ranges(fake_server):
    test_data = b'thefakedata'*10
    def reader():
        return test_data
    address, server = fake_server(reader, None, enable_ranges=True)

    client = aioclient.AIOClient(
        address=address,
        chunk_size=1234,
        range_size=16,
    )

    data = b''
    with NamedTemporaryFile() as f:
        async with client as c:
            await c.read_to_file('/', f.name)
        f.seek(0)
        data = f.read()

    assert data == test_data


async def test_aioclient_read_to_file_100_ranges(fake_server):
    test_data = b'thefakedata'*10000
    def reader():
        return test_data
    address, server = fake_server(reader, None, enable_ranges=True)

    client = aioclient.AIOClient(
        address=address,
        chunk_size=1234,
        range_size=16,
    )

    data = b''
    with NamedTemporaryFile() as f:
        async with client as c:
            await c.read_to_file('/', f.name)
        f.seek(0)
        data = f.read()

    assert data == test_data


async def test_aioclient_read_to_file_ranges_too_small(fake_server):
    test_data = b'thefakedata'
    def reader():
        return test_data
    address, server = fake_server(reader, None, enable_ranges=True)

    client = aioclient.AIOClient(
        address=address,
        chunk_size=1234,
        range_size=16,
    )

    data = b''
    with NamedTemporaryFile() as f:
        async with client as c:
            await c.read_to_file('/', f.name)
        f.seek(0)
        data = f.read()

    assert data == test_data


async def test_aioclient_read_to_file_ranges_exactly_one(fake_server):
    test_data = b't'*16
    def reader():
        return test_data
    address, server = fake_server(reader, None, enable_ranges=True)

    client = aioclient.AIOClient(
        address=address,
        chunk_size=1234,
        range_size=16,
    )

    data = b''
    with NamedTemporaryFile() as f:
        async with client as c:
            await c.read_to_file('/', f.name)
        f.seek(0)
        data = f.read()

    assert data == test_data


async def test_aioclient_read_to_file_ranges_exactly_three(fake_server):
    test_data = b't'*16*3
    def reader():
        return test_data
    address, server = fake_server(reader, None, enable_ranges=True)

    client = aioclient.AIOClient(
        address=address,
        chunk_size=1234,
        range_size=16,
    )

    data = b''
    with NamedTemporaryFile() as f:
        async with client as c:
            await c.read_to_file('/', f.name)
        f.seek(0)
        data = f.read()

    assert data == test_data


async def test_aioclient_write_iter(fake_server):
    test_data = b'thefakedata'
    def writer(data):
        writer.data += data
    writer.data = b''
    address, server = fake_server(None, writer)

    client = aioclient.AIOClient(
        address=address,
        chunk_size=1234,
        range_size=5678,
    )

    async with client as c:
        await c.write_iter('/', test_data)

    assert writer.data == test_data
