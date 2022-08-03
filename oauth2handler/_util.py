"""
Utility Functions
"""

__all__ = [
    'ENV_VARS',
    ]

ENV_VARS = {
    'client_id': 'CLIENT_ID',
    'client_secret': 'CLIENT_SECRET',
    'token_uri': 'TOKEN_URI',
    'redirect_uri': 'REDIRECT_URI',
    'authorize_uri': 'AUTHORIZE_URI',
    'refresh_uri': 'REFRESH_URI',
}

import requests
import time
import os

from http.server import BaseHTTPRequestHandler, HTTPServer

from .errors import *

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.path
        self.server.url = self.path

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

        self._write('<!DOCTYPE html><html><script>window.close()</script></html>')

    def _write(self, text: str):
        return self.wfile.write(text.encode('utf-8'))

    def log_message(self, *args, **kwargs):
        return


def start_local_http_server(port: int) -> HTTPServer:
    server = HTTPServer(('127.0.0.1', port), RequestHandler)
    server.allow_reuse_address = True
    server.auth_code = None
    server.auth_token_form = None
    server.error = None
    return server

def get_response_json(resp: requests.Response, expected_values: list=None) -> dict:
    try:
        resp_json = resp.json()
    except requests.JSONDecodeError:
        raise ValueError(f'Response doesn\'t contain json. Content: {resp.text}')

    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        message = ''

        error = None
        if 'error' in resp_json:
            error = resp_json['error']
            message += f'Error: {error} '

        description = None
        if 'description' in resp_json:
            error = resp_json['description']
            message += f'Description: {description}'

        if error is None and description is None:
            message = resp_json

        raise OAuthError(
            message=message,
            error=error,
            error_description=description,
            )

    if expected_values is not None:
        for v in expected_values:
            if v not in resp_json:
                raise TypeError(f'Required parameter {v} wasn\'t found in the response. Content: {resp_json}')
    
    return resp_json

def validate_token(token: dict, state: str):
    if token['state'] != state:
        raise InvalidState(state, token['state'])

def check_token(token: dict) -> bool:
    now = int(time.time())
    return token['expires_at'] - now < 60

def ensure_value(value, value_name: str) -> str:
    value = value or os.getenv(ENV_VARS[value_name])
    if value is None:
        raise TypeError(f"Missing required argument: '{value_name}'")
    return value
