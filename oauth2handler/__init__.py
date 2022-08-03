"""
A simple yet effective wrapper for oauth2 APIs.
"""

__version__ = '1.0.0'

from . import cache_handler
from . import errors
from ._client import Client
from ._util import ENV_VARS
from . import auth