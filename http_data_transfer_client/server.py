"""
Server for user management
"""

import asyncio
import logging
from secrets import token_hex
import socket
import webbrowser

from tornado.web import authenticated
from rest_tools.server import RestServer, RestHandlerSetup, RestHandler, OpenIDLoginHandler
from wipac_dev_tools import from_environment


logger = logging.getLogger('token_server')


class Main(RestHandler):
    def initialize(self, state=None, **kwargs):
        super().initialize(**kwargs)
        if state is None:
            raise Exception('state must be a dict')
        self.state = state

    def get_current_user(self):
        try:
            self.state['access_token'] = self.get_secure_cookie('access_token', max_age_days=1)
            self.state['refresh_token'] = self.get_secure_cookie('refresh_token', None, max_age_days=1)
            return self.state['access_token']
        except Exception:
            self.state['access_token'] = None
            self.state['refresh_token'] = None
            return None

    @authenticated
    async def get(self):
        logger.debug('self.state: %r', self.state)
        self.write('Login successful. Return to terminal.')


def get_ephemeral_port():
    """Get an ephemeral port number."""
    # https://unix.stackexchange.com/a/132524
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    addr = s.getsockname()
    ephemeral_port = addr[1]
    s.close()
    return ephemeral_port


def create_server(state, oidc_url, client_id, client_secret=None):
    default_config = {
        'DEBUG': False,
        'COOKIE_SECRET': token_hex(64),
    }
    config = from_environment(default_config)

    rest_config = {
        'debug': config['DEBUG'],
        'auth': {
            'openid_url': oidc_url,
            'audience': client_id,
        }
    }

    kwargs = RestHandlerSetup(rest_config)

    main_args = {'state': state}
    main_args.update(kwargs)

    scopes = ['posix']
    if client_secret:
        scopes.append('offline_access')  # for refresh token
    logger.debug('scopes: %r', scopes)
    login_args = {
        'oauth_client_id': client_id,
        'oauth_client_secret': client_secret,
        'oauth_client_scope': ' '.join(scopes),
    }
    login_args.update(kwargs)

    host = 'localhost'
    port = get_ephemeral_port()
    address = f'http://{host}:{port}'

    server = RestServer(debug=config['DEBUG'], cookie_secret=config['COOKIE_SECRET'],
                        login_url=f'{address}/login')
    server.add_route('/', Main, main_args)
    server.add_route('/login', OpenIDLoginHandler, login_args)

    server.startup(address=host, port=port)

    return server, address


async def token_server(browser=True, **kwargs):
    state = {}
    server, address = create_server(state, **kwargs)
    logger.info('token server listening on %s', address)

    print('Requesting new token authorization.  Please open:')
    print('  ', address)
    if browser:
        try:
            webbrowser.open_new_tab(address)
        except Exception:
            pass

    while not state.get('access_token', None):
        logger.debug('state: %r', state)
        await asyncio.sleep(.1)

    logger.info('token server going down')
    await server.stop()
    logger.info('token server stopped')

    access_token = state.get('access_token', None)
    if access_token and isinstance(access_token, bytes):
        access_token = access_token.decode('utf-8')

    refresh_token = state.get('refresh_token', None)
    if refresh_token and isinstance(refresh_token, bytes):
        refresh_token = refresh_token.decode('utf-8')

    return access_token, refresh_token
