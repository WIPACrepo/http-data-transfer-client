import asyncio
from copy import deepcopy
import logging
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from typing import Any, BinaryIO, Callable, Dict, Iterable, Optional, Union

import aiohttp
import jwt
from rest_tools.utils.auth import OpenIDAuth

from .auth import check_expiration, TOKEN_EXPIRE_DELAY_OFFSET


logger = logging.getLogger('aioclient')


class AIOClient:
    """An async REST client

    No auth.

    Args:
        address (str): base address of REST API
        chunk_size (int): size of iterable chunks
        total_timeout (float): total request timeout (optional)
        idle_timeout (float): idle request timeout (optional)
    """
    def __init__(
        self,
        address: str,
        chunk_size: int = 1024*64,
        range_size: int = 1024*1024*64,  # 64 MB chunks
        total_timeout: float = 3600.0,
        idle_timeout: float = 60.0,
        retries: int = 2,
        **kwargs
    ) -> None:
        self.address = address

        self.chunk_size = chunk_size
        self.range_size = range_size
        timeout = aiohttp.ClientTimeout(total=total_timeout, connect=idle_timeout, sock_connect=idle_timeout)
        self.session = aiohttp.ClientSession(timeout=timeout, raise_for_status=True)

    async def __aenter__(self):
        await self._get_token()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.session.close()
        await asyncio.sleep(.25)

    async def _get_token(self) -> None:
        return None

    async def _prepare(self, route: str) -> None:
        kwargs: Dict[str, Any] = {
            'url': self.address + route,
            'headers': {},
        }

        token = await self._get_token()
        if token:
            kwargs['headers'] = {
                'Authorization': 'Bearer '+token,
            }

        return kwargs

    async def read_iter(self, route: str) -> Iterable[bytes]:
        kwargs = await self._prepare(route)
        async with self.session.get(**kwargs) as resp:
            logger.debug('headers: %r', resp.headers)
            async for chunk in resp.content.iter_chunked(self.chunk_size):
                yield chunk

    async def _read_to_file_helper(self, filename: str, **kwargs) -> None:
        with open(filename, 'wb') as f:
            async with self.session.get(**kwargs) as resp:
                async for chunk in resp.content.iter_chunked(self.chunk_size):
                    f.write(chunk)

    async def read_to_file(self, route: str, filename: str) -> None:
        kwargs = await self._prepare(route)
        ranges = None
        async with self.session.head(**kwargs) as resp:
            logger.debug('headers: %r', resp.headers)
            if resp.headers.get('Accept-Ranges', None) == 'bytes':
                size = int(resp.headers.get('Content-Length', 0))
                if size > self.range_size:
                    ranges = []
                    range_size = size//100 if size > 100*self.range_size else self.range_size
                    i = 0
                    while i < size:
                        end = i+range_size-1
                        if end >= size:
                            end = size-1
                        ranges.append((i, end))
                        i += range_size

        if not ranges:
            logger.info('read_to_file: standard download')
            await self._read_to_file_helper(filename, **kwargs)
        else:
            logger.info('read_to_file: %d ranges', len(ranges))
            async def get_part(args):
                await asyncio.create_task(self._read_to_file_helper(args['filename'], **args['task_args']))
                return args

            with open(filename, 'wb') as outfile, TemporaryDirectory() as tmpdir:
                tasks = set()
                for i, (begin, end) in enumerate(ranges):
                    task_args = deepcopy(kwargs)
                    task_args['headers']['Range'] = f'bytes={begin}-{end}'
                    tmpfilename = Path(tmpdir) / f'{i}.part'
                    args = {
                        'index': i,
                        'range': (begin, end),
                        'filename': tmpfilename,
                        'task_args': task_args,
                    }
                    tasks.add(asyncio.create_task(get_part(args)))
                while tasks:
                    done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    logger.info('reading ranges, %d of %d complete', len(ranges)-len(tasks), len(ranges))
                    for t in done:
                        ret = await t
                        logger.debug('processing part %d: %r', ret['index'], ret['range'])
                        begin, end = ret['range']
                        if end-begin+1 != os.path.getsize(ret['filename']):
                            logger.debug('range size mismatch: asked for %d bytes, received %d bytes', end-begin+1, os.path.getsize(ret['filename']))
                            raise Exception(f'part {ret["index"]} is incomplete')
                        outfile.seek(begin)
                        with open(ret['filename'], 'rb') as f:
                            while chunk := f.read(self.chunk_size):
                                outfile.write(chunk)
                        outfile.flush()

    async def write_iter(self, route: str, data: Union[bytes, BinaryIO]) -> None:
        kwargs = await self._prepare(route)
        async with self.session.put(data=data, **kwargs) as resp:
            logger.debug('headers: %r', resp.headers)


class AIO_Token_Client(AIOClient):
    """Async token auth REST client

    Takes a token, no refresh.

    Args:
        access_token (str): access token
    """
    def __init__(
        self,
        *args,
        access_token: str,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.access_token: Optional[str] = access_token

    async def _get_token(self) -> str:
        if self.access_token:
            # check if expired
            try:
                check_expiration(self.access_token)
                return self.access_token
            except Exception:
                self.access_token = None
                logger.debug('access token expired')

        raise Exception('No token available / token expired')


class AIO_OIDC_Client(AIOClient):
    """OIDC async REST client

    Can handle token refresh using OpenID .well-known auto-discovery.

    Args:
        token_url (str): base address of token service
        refresh_token (str): initial refresh token
        client_id (str): client id
        client_secret (str): client secret (optional - required for refresh tokens)
        update_func (callable): a function that gets called when the access and refresh tokens are updated (optional)
    """
    def __init__(
        self,
        *args,
        token_url: str,
        refresh_token: str,
        client_id: str,
        client_secret: Optional[str] = None,
        update_func: Optional[Callable[[Union[str, bytes], Optional[Union[str, bytes]]], None]] = None,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.auth = OpenIDAuth(token_url)
        self.client_id = client_id
        self.client_secret = client_secret

        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = refresh_token
        self.update_func = update_func

    async def _get_token(self) -> str:
        if self.access_token:
            # check if expired
            try:
                data = self.auth.validate(self.access_token)
                if data['exp'] < time.time()-TOKEN_EXPIRE_DELAY_OFFSET:
                    raise Exception()
                return self.access_token
            except Exception:
                self.access_token = None
                logger.debug('OpenID token expired')

        if self.refresh_token:
            # try the refresh token
            args = {
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token,
                'client_id': self.client_id,
            }
            if self.client_secret:
                args['client_secret'] = self.client_secret

            try:
                async with self.session.post(self.auth.token_url, data=args, raise_for_status=False) as resp:
                    if resp.status == 200:
                        req = await resp.json()
                    else:
                        body = await resp.text()
                        logger.debug('body %r', body)
                        raise Exception()
            except Exception:
                logger.debug('error refreshing token', exc_info=True)
                self.refresh_token = None
            else:
                logger.debug('OpenID token refreshed')
                self.access_token = req['access_token']
                self.refresh_token = req['refresh_token'] if 'refresh_token' in req else None
                if self.access_token and self.update_func:
                    self.update_func(self.access_token, self.refresh_token)
                return self.access_token

        raise Exception('No token available / token expired')
