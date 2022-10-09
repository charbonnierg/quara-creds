import abc

from quara.creds.nebula import SigningKeyPair


class CAKeyStore(metaclass=abc.ABCMeta):
    """A store holding CA signing keys"""

    @abc.abstractmethod
    def get_ca_key(self, name: str) -> SigningKeyPair:
        """Get CA key for a given CA name"""
        raise NotImplementedError
