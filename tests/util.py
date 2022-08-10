from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
import pytest
from rest_tools.server import RestHandlerSetup, RestHandler, RestServer

from http_data_transfer_client.server import get_ephemeral_port


@pytest.fixture(scope="session")
def gen_keys():
    priv = generate_private_key(65537, 2048)
    pub = priv.public_key()
    return (priv, pub)

@pytest.fixture(scope="session")
def gen_keys_bytes(gen_keys):
    priv, pub = gen_keys

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print(priv_pem, pub_pem)
    return (priv_pem, pub_pem)

class FakeHandler(RestHandler):
    def initialize(self, read_callback, write_callback, enable_ranges=False, **kwargs):
        self.read_callback = read_callback
        self.write_callback = write_callback
        self.enable_ranges = enable_ranges
        super().initialize(**kwargs)

    def head(self):
        if self.enable_ranges and self.read_callback:
            self.set_header('Accept-Ranges', 'bytes')
            self.set_header('Content-Length', str(len(self.read_callback())))

    def get(self):
        data = self.read_callback()
        if self.enable_ranges and self.request.headers.get('Range', False):
            begin, end = (int(x) for x in self.request.headers['Range'].split('=')[1].split('-'))
            if end >= len(data):
                end = len(data)-1
            self.set_status(206)
            self.set_header('Content-Range', f'bytes {begin}-{end}/{len(data)}')
            self.set_header('Content-Length', f'{end-begin+1}')
            self.write(data[begin:end+1])
        else:
            self.write(data)

    def put(self):
        self.write_callback(self.request.body)


@pytest.fixture
def fake_server():
    def start_server(read, write, **kwargs):
        port = get_ephemeral_port()
        address = f'http://localhost:{port}'
        args = RestHandlerSetup()
        args['read_callback'] = read
        args['write_callback'] = write
        args.update(kwargs)
        server = RestServer()
        server.add_route(r'/.*', FakeHandler, args)
        server.startup(port=port)
        return address, server
    return start_server
