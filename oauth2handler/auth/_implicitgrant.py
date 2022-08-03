__all__ = [
    'ImplicitGrant',
    ]

import urllib.parse
import webbrowser
import logging
import time

from ._authbase import AuthBase
from .._util import ensure_value, validate_token
from ..cache_handler import CacheHandler, MemoryCacheHandler

logger = logging.getLogger(__name__)

class ImplicitGrant(AuthBase):
    def __init__(
        self,
        client_id: str=None,
        redirect_uri: str=None,
        authorize_uri: str=None,
        scope: str='',
        state: str='',
        cache_handler=None,
    ):
        """
        Implicit Grant returns the token in the redirect url.
        Doesn't support refreshing the token.
        It becomes easy to intercept the token.

        Parameters:
            * client_id: Required, Your client's id, Can be supplied as a env var.
            * redirect_uri: Required, The page the user is redirected to after authentication, Can be supplied as a env var.
            * authorize_uri: Required, The page to get authorization from the user, Can be supplied as a env var.
            * scope: Optional, A list of scopes your app needs.
                You shouldn't request more scopes than you need
            * state: Optional, Highly Recommended, Great for security.
            * cache_handler: Optional, A cache handler that inherits from the CacheHandler class.
                Defaults to memeory
        """
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.authorize_uri = authorize_uri
        self.state = state
        self.scope = scope
        self.cache_handler = cache_handler

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

    @property
    def cache_handler(self):
        return self._cache_handler

    @cache_handler.setter
    def cache_handler(self, value):
        self._cache_handler = value

    def get_access_token(self, check_cache: bool=True, url=None) -> str:
        """
        Get the cached token or get a new token.

        Parameters:
            * check_cache: Optional, Whether or not to check the cache for a token.
            * url: Optional, The url the user was redirected to after authenticating the app.
        """
        if check_cache:
            token = self._cache_handler.get_cached_token()
            if token:
                if not self.is_token_expired(token):
                    return token['access_token']
        if url is None:
            token = self._request_access_token()
        else:
            token = self._parse_url(url)
        token = self._add_custom_values_to_token(token)
        
        self._cache_handler.set_cached_token(token)
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
            'response_type': 'token',
            'scope': self._scope,
            'state': self._state,
        }
        auth_url = f'{self._authorize_uri}?{urllib.parse.urlencode(params)}'
        return auth_url

    def _request_access_token(self):
        self._open_auth_url()
        url = input('Url of site: \n')
        token = self._parse_url(url)
        if self._state:
            validate_token(token, self._state)
        return token

    def _parse_url(self, url: str) -> dict:
        parsedurl = urllib.parse.urlparse(url)[5]
        query_params = urllib.parse.parse_qs(parsedurl, keep_blank_values=True)
        for i in query_params:
            query_params[i] = query_params[i][0]
        return query_params

    def _add_custom_values_to_token(self, token: dict) -> dict:
        token.setdefault('expires_in', 0)
        token.setdefault('scope', self._scope)
        token['expires_at'] = int(time.time()) + int(token['expires_in'])
        return token
