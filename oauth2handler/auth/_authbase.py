__all__ = [
    'AuthBase',
    ]

class AuthBase:
    def __init__(self):
        """
        All auth classes inherit from this one.
        """
        pass

    def get_access_token(self) -> str:
        raise NotImplementedError()