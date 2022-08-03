"""
The errors that can occur during runtime.
"""

__all__ = [
    'OAuthError',
    'InvalidState',
    ]

class OAuthError(Exception):
    def __init__(self, message, error=None, error_description=None, *args, **kwargs):
        """
        Something happened during auth.
        """
        self.error = error
        self.error_description = error_description
        super().__init__(message, *args, **kwargs)


class InvalidState(OAuthError):
    def __init__(self, local_state, remote_state, *args, **kwargs):
        """
        The state recieved and the state expected weren't the same
        """
        message = f'Expected: {local_state} Got: {remote_state}'
        super().__init__(*args, message=message, **kwargs)
        