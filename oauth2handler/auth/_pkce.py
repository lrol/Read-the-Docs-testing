__all__ = [
    'PKCE',
    ]

import urllib.parse
import webbrowser
import requests
import logging
import time

from ._authbase import AuthBase
from .._util import start_local_http_server, get_response_json, validate_token, ensure_value, check_token
from ..cache_handler import CacheHandler, MemoryCacheHandler

logger = logging.getLogger(__name__)

class PKCE(AuthBase):
    def __init__(
        self,
        client_id: str=None,
        redirect_uri: str=None,
        authorize_uri: str=None,
        token_uri: str=None,
        refresh_uri: str=None,
        scope: str='',
        state: str='',
        requests_session: requests.Session=None,
        proxies: dict=None,
        requests_timeout: int=None,
        web_browser: bool=True,
        cache_handler=None,
    ):
        """
        PKCE is a extension of the OAuth method and allows for secure authentication without a client secret.
        Use this for when the client secret cannot be stored securily.
        Allows user endpoints.

        Parameters:
            * client_id: Required, Your client's id, Can be supplied as a env var.
            * redirect_uri: Required, The page the user is redirected to after authentication, Can be supplied as a env var.
            * authorize_uri: Required, The page to get authorization from the user, Can be supplied as a env var.
            * token_uri: Required, The url to request a token from, Can be supplied as a env var.
            * refresh_uri: Required, The url to refresh the access token, Can be supplied as a env var.
                If you can't find it try using the token url here.
            * scope: Optional, A list of scopes your app needs.
                You shouldn't request more scopes than you need
            * state: Optional, Highly Recommended, Great for security from CSRF attacks.
            * requests_session: Optional, A requests session to use.
            * proxies: Optional, The proxie for the request session to use.
            * requests_timeout: Optional, The time to stop waiting for a response.
            * web_broswer: Optional, Whether or not to automatically retrieve auth url.
                Only matters if the redirect url is localhost or something similar.
            * cache_handler: Optional, A cache handler that inherits from the CacheHandler class.
                Defaults to memeory
        """
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.authorize_uri = authorize_uri
        self.refresh_uri = refresh_uri
        self.token_uri = token_uri
        self.state = state
        self.scope = scope
        self._proxies = proxies
        self._requests_timeout = requests_timeout
        self._web_browser = web_browser
        self._verifier = ''
        self._challenge = ''

        if isinstance(cache_handler, CacheHandler):
            self.cache_handler = cache_handler
        else:
            self.cache_handler = MemoryCacheHandler()

        if isinstance(requests_session, requests.Session):
            self._session = requests_session
        else:
            self._session = requests.Session()
        self.get_handshake_parameters()

    @property
    def client_id(self) -> str:
        return self._client_id

    @client_id.setter
    def client_id(self, value: str):
        self._client_id = ensure_value(value, 'client_id')

    @property
    def redirect_uri(self) -> str:
        return self._redirect_uri

    @redirect_uri.setter
    def redirect_uri(self, value: str):
        self._redirect_uri = ensure_value(value, 'redirect_uri')

    @property
    def authorize_uri(self) -> str:
        return self._authorize_uri

    @authorize_uri.setter
    def authorize_uri(self, value: str):
        self._authorize_uri = ensure_value(value, 'authorize_uri')

    @property
    def refresh_uri(self) -> str:
        return self._refresh_uri

    @authorize_uri.setter
    def refresh_uri(self, value: str):
        self._refresh_uri = ensure_value(value, 'refresh_uri')

    @property
    def token_uri(self) -> str:
        return self._token_uri

    @token_uri.setter
    def token_uri(self, value: str):
        self._token_uri = ensure_value(value, 'token_uri')

    @property
    def cache_handler(self):
        return self._cache_handler

    @property
    def state(self) -> str:
        return self._state
    
    @state.setter
    def state(self, value: str):
        self._state = urllib.parse.quote_plus(value)

    @property
    def scope(self) -> str:
        return self._scope

    @scope.setter
    def scope(self, value: str):
        self._scope = value

    @cache_handler.setter
    def cache_handler(self, value):
        self._cache_handler = value

    def get_access_token(self, check_cache: bool=True, url: str=None) -> str:
        """
        Get the cached token or get a new token.

        Parameters:
            * check_cache: Optional, Whether or not to check the cache for a token.
            * url: Optional, The url the user was redirected to after authenticating the app.
                Used for backend servers.
        """
        if check_cache:
            token = self.cache_handler.get_cached_token()
            if token:
                if check_token(token):
                    token = self._refresh_access_token(token['refresh_token'])
                    self._add_custom_values_to_token(token)
                    self.cache_handler.set_cached_token(token)
                    return token['access_token']
                else:
                    return token['access_token']
        token = self._request_access_token(url)
        self._add_custom_values_to_token(token)
        
        validate_token(token, self._state)
        
        self.cache_handler.set_cached_token(token)
        return token['access_token']

    def _open_auth_url(self):
        url = self.get_auth_url()
        webbrowser.open(url)
        logger.debug(f'Opened {url} in browser')
        
    def get_auth_url(self) -> str:
        """
        Get the authentication url to redirect the user to.
        """
        params = {
            'client_id': self._client_id,
            'redirect_uri': self._redirect_uri,
            'response_type': 'code',
            'scope': self._scope,
            'state': self._state,
            'code_challenge': self._challenge,
            'code_challenge_method': 'S256',
        }
        auth_url = f'{self._authorize_uri}?{urllib.parse.urlencode(params)}'
        return auth_url

    def _get_exchange_code(self) -> str:
        parsed_redirect = urllib.parse.urlparse(self._redirect_uri)
        redirect_host, redirect_port = parsed_redirect[1].split(':', 1)
        redirect_port = int(redirect_port)

        if (
            self._web_browser
            and redirect_host in ('127.0.0.1', 'localhost')
            and parsed_redirect[0] == 'http'
        ):
            url = self._get_url_automatic(redirect_port)
        else:
            url = self._get_url_interactive()

        return url

    def _exchange_code(self, code: str) -> dict:
        data = {
            'client_id': self._client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self._redirect_uri,
            'code_verifier': self._verifier,
        }

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json',}

        logger.debug(f'Sending post request to {self._token_uri} with data: {data} and headers: {headers}')

        response = self._session.post(
            self._token_uri,
            data=data,
            headers=headers,
            proxies=self._proxies,
            timeout=self._requests_timeout,
        )
        token = get_response_json(response)
        return token

    def _parse_url(self, url: str) -> str:
        query_params = urllib.parse.parse_qs(urllib.parse.urlparse(url)[4])
        code = query_params['code']
        if self._state:
            validate_token(query_params, self._state)
        return code

    def _get_url_automatic(self, port):
        server = start_local_http_server(port)
        self._open_auth_url()
        server.handle_request()
        return server.url

    def _get_url_interactive(self):
        self._open_auth_url()
        return input('Url of site: \n')

    def _request_access_token(self, url=None):
        if not self._verifier:
            self.get_handshake_parameters()

        if url is None:
            url = self._get_exchange_code()

        code = self._parse_url(url)

        token = self._exchange_code(code)
        return token

    def _refresh_access_token(self, refresh_token):
        data = {
            'client_id': self._client_id,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token',
            'scope': self._scope,
        }

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json'}

        logger.debug(f'Sending post request to {self._token_uri} with data: {data} and headers: {headers}')

        response = self._session.post(
            self._refresh_uri,
            data=data,
            headers=headers,
            proxies=self._proxies,
            timeout=self._requests_timeout,
            )
        token = get_response_json(response)
        token.setdefault('refresh_token', refresh_token)
        return token

    def get_handshake_parameters(self):
        self._verifier = self._make_verifier()
        self._challenge = self._get_challenge(self._verifier)

    def _make_verifier(self):
        import random
        import secrets

        length = random.randint(33, 96)
        return secrets.token_urlsafe(length)

    def _get_challenge(self, verifier: str) -> str:
        import hashlib
        from base64 import urlsafe_b64encode

        hashed = hashlib.sha256(verifier.encode('ascii')).digest()
        encoded = urlsafe_b64encode(hashed)
        return encoded.decode('ascii')[:-1]

    def _add_custom_values_to_token(self, token: dict) -> dict:
        token.setdefault('expires_in', 0)
        token.setdefault('refresh_token', None)
        token.setdefault('state', self._state)
        token['expires_at'] = int(time.time()) + token['expires_in']
        token['scope'] = self._scope
        