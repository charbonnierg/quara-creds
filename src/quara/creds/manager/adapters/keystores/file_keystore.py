import typing as t
from pathlib import Path

from quara.creds.manager.interfaces.keystore import CAKeyStore
from quara.creds.nebula import SigningKeyPair


class FileCAKeyStore(CAKeyStore):
    """A filesystem store"""

    def __init__(self, root: t.Union[str, Path]) -> None:
        self.root = Path(root)

    def get_ca_key(self, name: str) -> SigningKeyPair:
        if not isinstance(name, str):
            raise TypeError(f"Name must be a string. Received {type(name)}")
        return SigningKeyPair.from_file(self.root / f"{name}.key")
