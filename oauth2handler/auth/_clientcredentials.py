__all__ = [
    'ClientCredentials',
    ]

import requests
import logging
import base64
import time

from ._authbase import AuthBase
from .._util import get_response_json, ensure_value, check_token
from ..cache_handler import CacheHandler, MemoryCacheHandler

logger = logging.getLogger(__name__)

class ClientCredentials(AuthBase):
    def __init__(
        self,
        client_id=None,
        client_secret=None,
        token_uri=None,
        cache_handler=None,
        requests_session=None,
        proxies=None,
        requests_timeout=None,
    ):
        """
        Client Credentials flow is used for server to server authentication.
        No user endpoints can be accessed.

        Parameters:
            * client_id: Required, Your client's id, Can be supplied as a env var.
            * client_secret: Required, Your client's secret, Can be supplied as a env var.
            * token_uri: Required, The url to request a token from, Can be supplied as a env var.
            * cache_handler: Optional, A cache handler that inherits from the CacheHandler class.
                Defaults to memeory.
            * requests_session: Optional, A requests session to use.
            * proxies: Optional, The proxie for the request session to use.
            * requests_timeout: Optional, The time to stop waiting for a response.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_uri = token_uri
        self.cache_handler = cache_handler
        self._proxies = proxies
        self._requests_timeout = requests_timeout

        if isinstance(requests_session, requests.Session):
            self._session = requests_session
        else:
            self._session = requests.Session()

    @property
    def client_id(self) -> str:
        return self._client_id

    @client_id.setter
    def client_id(self, value: str):
        self._client_id = ensure_value(value, 'client_id')

    @property
    def client_secret(self) -> str:
        return self._client_secret

    @client_secret.setter
    def client_secret(self, value: str):
        self._client_secret = ensure_value(value, 'client_secret')

    @property
    def token_uri(self) -> str:
        return self._token_uri

    @token_uri.setter
    def token_uri(self, value: str):
        self._token_uri = ensure_value(value, 'token_uri')

    @property
    def cache_handler(self):
        return self._cache_handler

    @cache_handler.setter
    def cache_handler(self, value):
        self._cache_handler = value

    def get_access_token(self, check_cache: bool=True) -> str:
        """
        Get the cached token or a new token.

        Parameters:
            * check_cache: Optional, Whether or not to check the cache for a token.
        """
        if check_cache:
            token = self._cache_handler.get_cached_token()
            if token is not None and not check_token(token):
                return token['access_token']

        token = self._request_access_token()
        token = self._add_custom_values_to_token(token)

        self._cache_handler.set_cached_token(token)
        return token['access_token']

    def _request_access_token(self) -> dict:
        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type': 'client_credentials',
        }

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json',
                   'Authorization': f'Basic {self._get_authorization_header()}'}

        logger.debug(f'Sending post request to {self._token_uri} with data: {data} and headers: {headers}')
        
        response = self._session.post(
            self._token_uri,
            data=data,
            verify=True,
            proxies=self._proxies,
            timeout=self._requests_timeout,
        )
        
        token = get_response_json(response, ['access_token'])
        return token

    def _get_authorization_header(self) -> str:
        auth_str = f'{self._client_id}:{self._client_secret}'.encode('ascii')
        return base64.urlsafe_b64encode(auth_str).decode('ascii')

    def _add_custom_values_to_token(self, token: dict) -> dict:
        token.setdefault('expires_in', 0)
        token['expires_at'] = int(time.time()) + token['expires_in']
        return token
        