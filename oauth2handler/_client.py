__all__ = [
    'Client',
    ]

import requests
import logging

logger = logging.getLogger(__name__)

class Client:
    def __init__(self, auth_manager, requests_session=None, proxies=None, requests_timeout=None):
        """
        A basic client for sending requests with auth headers.

        Parameters:
            * auth_manager: Required, A auth manager that inherits from the AuthBase class.
            * requests_session: Optional, A requests session for the client to use.
            * proxies: Optional, The proxie for the request session to use.
            * requests_timeout: Optional, The time to stop waiting for a response.
        """
        self.auth_manager = auth_manager
        self._proxies = proxies
        self._requests_timeout = requests_timeout
        if isinstance(requests_session, requests.Session):
            self._session = requests_session
        else:
            self._session = requests.Session()
        self._update_token()

    @property
    def auth_manager(self):
        return self._auth_manager

    @auth_manager.setter
    def auth_manager(self, value):
        self._auth_manager = value

    def _update_token(self):
        token = self._auth_manager.get_access_token()
        header = {'Authorization': f'Bearer {token}'}
        logger.debug(f'Adding headers: {header}')
        self._session.headers.update(header)

    def request(self, *args, **kwargs) -> requests.Response:
        """
        Send a request with the auth headers.
        """
        self._update_token()
        logger.debug(f'Sending a request with arguments: {args}, and kwargs: {kwargs}')
        return self._session.request(*args, **kwargs, proxies=self._proxies, timeout=self._requests_timeout)

    def get(self, *args, **kwargs) -> requests.Response:
        """
        Send a get request with the auth headers.
        """
        self._update_token()
        logger.debug(f'Sending a get request with arguments: {args}, and kwargs: {kwargs}')
        return self._session.get(*args, **kwargs, proxies=self._proxies, timeout=self._requests_timeout)

    def post(self, *args, **kwargs) -> requests.Response:
        """
        Send a post request with the auth headers.
        """
        self._update_token()
        logger.debug(f'Sending a post request with arguments: {args}, and kwargs: {kwargs}')
        return self._session.post(*args, **kwargs, proxies=self._proxies, timeout=self._requests_timeout)

    def put(self, *args, **kwargs) -> requests.Response:
        """
        Send a put request with the auth headers.
        """
        self._update_token()
        logger.debug(f'Sending a put request with arguments: {args}, and kwargs: {kwargs}')
        return self._session.put(*args, **kwargs, proxies=self._proxies, timeout=self._requests_timeout)

    def delete(self, *args, **kwargs) -> requests.Response:
        """
        Send a delete request with the auth headers.
        """
        self._update_token()
        logger.debug(f'Sending a delete request with arguments: {args}, and kwargs: {kwargs}')
        return self._session.delete(*args, **kwargs, proxies=self._proxies, timeout=self._requests_timeout)

    def head(self, *args, **kwargs) -> requests.Response:
        """
        Send a head request with the auth headers.
        """
        self._update_token()
        return self._session.head(*args, **kwargs, proxies=self._proxies, timeout=self._requests_timeout)

    def options(self, *args, **kwargs) -> requests.Response:
        """
        Send a options request with the auth headers.
        """
        self._update_token()
        logger.debug(f'Sending a options request with arguments: {args}, and kwargs: {kwargs}')
        return self._session.options(*args, **kwargs, proxies=self._proxies, timeout=self._requests_timeout)
