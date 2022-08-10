import asyncio
import argparse
import json
import logging
from pathlib import Path
from urllib.parse import urlparse

from appdirs import user_config_dir
from wipac_dev_tools import from_environment

from .aioclient import AIO_Token_Client, AIO_OIDC_Client
from .auth import check_expiration
from .server import token_server


logger = logging.getLogger('http-data-transfer-client')


def _conf_file():
    return Path(user_config_dir('http-data-transfer-client')) / 'tokens.json'


def store_tokens(access_token, refresh_token=None):
    config = _conf_file()
    data = {'access_token': access_token, 'refresh_token': refresh_token}
    logger.debug('store_tokens: %s', config)

    config.parent.mkdir(parents=True, exist_ok=True)
    with open(config, 'w') as f:
        json.dump(data, f, sort_keys=True, indent=4)


def load_tokens():
    config = _conf_file()
    access_token = None
    refresh_token = None

    if config.is_file():
        logger.debug('load_tokens: %s', config)
        data = {}
        with open(config) as f:
            data = json.load(f)

        at = data.get('access_token', None)
        if at:
            try:
                check_expiration(at)
            except Exception:
                logger.debug('expired stored token')
            else:
                access_token = at

        rt = data.get('refresh_token', None)
        if rt:
            try:
                check_expiration(rt)
            except Exception:
                logger.debug('expired stored token')
            else:
                refresh_token = rt

    return access_token, refresh_token


def _get_base_url(filename):
    url = urlparse(filename)
    if (not url.scheme) or not url.netloc:
        return ''
    return f'{url.scheme}://{url.netloc}'


def get_rest_url(source_files, dest_file):
    source_urls = [_get_base_url(f) for f in source_files]
    source_http = any(u for u in source_urls)
    dest_url = _get_base_url(dest_file)

    if (not source_http) and not dest_url:
        raise RuntimeError('Neither a source or a dest is an http address!')
    elif source_http and dest_url:
        raise RuntimeError('Both source and dest cannot be http addresses!')
    elif source_http and not all(source_urls):
        raise RuntimeError('Not all sources are http addresses!')

    base_url = source_urls[0] if source_http else dest_url
    if source_http and not all(u == base_url for u in source_urls):
        raise RuntimeError('Sources are from different domains!')

    return base_url


async def _get_file(source, dest, rest_client=None):
    matching_dest = dest / Path(source).name if dest.is_dir() else dest
    await rest_client.read_to_file(source, filename=matching_dest)


async def _put_file(source, dest, rest_client=None):
    if not source.is_file():
        raise Exception(f'File {source} does not exist')
    with open(source, 'rb') as f:
        await rest_client.write_iter(dest, f)


async def do_transfer(source_files, dest_file, rest_client=None):
    if rest_client is None:
        raise Exception('invalid rest client')

    source_urls = [_get_base_url(f) for f in source_files]
    source_http = any(u for u in source_urls)
    dest_url = _get_base_url(dest_file)

    # just checking that nothing snuck in from previous check
    if source_http:
        assert not dest_url
    if dest_url:
        assert not source_http

    tasks = []
    for source_file in source_files:
        if source_http:
            source = urlparse(source_file).path
            dest = Path(dest_file)
            if len(source_files) > 1 and not dest.is_dir():
                raise Exception('dest must be an existing directory for multiple source files')
            logger.warning('get file: %s %s', source, dest)
            tasks.append(_get_file(source, dest, rest_client=rest_client))
        else:
            source = Path(source_file)
            dest = urlparse(dest_file).path
            if dest_file.endswith('/'):
                dest = dest + source.name
            logger.warning('put file: %s %s', source, dest)
            tasks.append(asyncio.create_task(_put_file(source, dest, rest_client=rest_client)))

    await asyncio.gather(*tasks)


async def main():
    default_config = {
        'AUTH_URL': 'https://keycloak.icecube.wisc.edu/auth/realms/IceCube/',
        'AUTH_CLIENT_ID': 'http-data-transfer-client',
        'AUTH_CLIENT_SECRET': 'NOT-PRESENT',
        'DEBUG': False,
        'RETRIES': 1,
        'TIMEOUT': 3600,
        'IDLE_TIMEOUT': 60,
    }
    config = from_environment(default_config)

    parser = argparse.ArgumentParser(prog='python -m http_data_transfer_client', description='http(s) data transfer tool')
    parser.add_argument('--no-browser', dest='browser', action='store_false', help='Do not automatically open a browser window. Instead, print the url to open manually.')
    parse_auth = parser.add_argument_group('Auth')
    parse_auth.add_argument('-a', '--auth-url', default=config['AUTH_URL'], help='OpenID auth url')
    parse_auth.add_argument('--auth-client-id', default=config['AUTH_CLIENT_ID'], help='Auth client ID')
    parse_auth.add_argument('--auth-client-secret', default=config['AUTH_CLIENT_SECRET'], help='Auth client secret (required for refresh tokens)')
    parse_auth.add_argument('--refresh-token', default=None, help='Directly supply the refresh token to use (will not generate internally)')
    parse_misc = parser.add_argument_group('Misc')
    parse_misc.add_argument('--range-size', default=None, type=int, help='Min range size, for range requests')
    parse_misc.add_argument('--total-timeout', default=config['TIMEOUT'], type=int, help='Transfer total timeout')
    parse_misc.add_argument('--idle-timeout', default=config['IDLE_TIMEOUT'], type=int, help='Transfer idle timeout')
    parse_misc.add_argument('--debug', type=bool, default=config['DEBUG'], help='Enable/disable debugging')
    parser.add_argument('source_files', nargs='+', help='Source file(s)')
    parser.add_argument('dest_file', help='Destination (can be a directory)')
    args = parser.parse_args()

    print(args)

    rest_url = get_rest_url(args.source_files, args.dest_file)

    access_token = None
    refresh_token = args.refresh_token
    if not refresh_token:
        # check for a cached token
        try:
            access_token, refresh_token = load_tokens()
        except Exception:
            logger.info('cannot load stored token')
            logger.debug('error', exc_info=True)

        if args.auth_client_secret != 'NOT-PRESENT' and not refresh_token:
            access_token = None  # must have refresh token in this case

        if access_token:
            logger.info('tokens loaded from cached config')

    if (not refresh_token) and not access_token:
        # load from web
        kwargs = {
            'browser': args.browser,
            'oidc_url': args.auth_url,
            'client_id': args.auth_client_id,
        }
        if args.auth_client_secret != 'NOT-PRESENT':
            kwargs['client_secret'] = args.auth_client_secret
        try:
            access_token, refresh_token = await token_server(**kwargs)
        except Exception:
            logger.info('cannot load token from web server')
            logger.debug('error', exc_info=True)

        if access_token:
            logger.info('tokens loaded from web')
            store_tokens(access_token, refresh_token)

    rc_kwargs = {
        'address': rest_url,
        'total_timeout': args.total_timeout,
        'idle_timeout': args.idle_timeout,
    }
    if args.range_size:
        rc_kwargs['range_size'] = args.range_size
    if refresh_token:
        logger.info('have refresh token - using OIDC client')
        rc_kwargs.update({
            'refresh_token': refresh_token,
            'token_url': args.auth_url,
            'client_id': args.auth_client_id,
            'update_func': store_tokens,
        })
        if args.auth_client_secret != 'NOT-PRESENT':
            rc_kwargs['client_secret'] = args.auth_client_secret
        rest_client = AIO_OIDC_Client(**rc_kwargs)
    elif access_token:
        logger.info('have access token - using token client')
        rc_kwargs['access_token'] = access_token,
        rest_client = AIO_Token_Client(**rc_kwargs)
    else:
        logger.info('have no tokens!')
        raise RuntimeError('Unable to use any auth tokens')

    # now do transfer
    async with rest_client as rc:
        await do_transfer(args.source_files, args.dest_file, rest_client=rc)
