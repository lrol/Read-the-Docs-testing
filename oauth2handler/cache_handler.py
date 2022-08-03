'''
The cache handlers required for caching tokens.
All cache handlers (custom or not) need to inherit the CacheHandler class 
and define get_cached_token and set_cached_token.
'''

__all__ = [
    'CacheHandler',
    'CacheFileHandler',
    'MemoryCacheHandler',
    ]

import json
import os

class CacheHandler:
    def __init__(self, token: dict=None):
        self.set_cached_token(token)

    def get_cached_token(self) -> dict:
        raise NotImplementedError()
    
    def set_cached_token(self, token) -> dict:
        raise NotImplementedError()

class CacheFileHandler(CacheHandler):
    def __init__(self, cache_path: str=None, token: dict=None):
        if cache_path:
            self.cache_path = cache_path
        else:
            cache_path = '.cache'
            self.cache_path = cache_path
        if token:
            self.set_cached_token(token)
        elif not self.get_cached_token():
            self.set_cached_token(None)

    def get_cached_token(self) -> dict:
        if os.path.exists(self.cache_path):
            with open(self.cache_path, 'r') as c:
                token = json.loads(c.read())
            return token
        else:
            return None

    def set_cached_token(self, token: dict):
        with open(self.cache_path, 'w') as c:
            c.write(json.dumps(token))

class MemoryCacheHandler(CacheHandler):
    def get_cached_token(self) -> dict:
        return self.token

    def set_cached_token(self, token: dict):
        self.token = token
        