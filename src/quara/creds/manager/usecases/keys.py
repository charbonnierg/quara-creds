import typing as t
from json import dumps

from quara.creds.nebula.api import (
    create_encryption_keypair,
    parse_encryption_keypair,
    parse_encryption_public_key,
)

if t.TYPE_CHECKING:
    from quara.creds.manager.manager import NebulaCertManager


class ManagedKeys:
    def __init__(self, manager: "NebulaCertManager") -> None:
        self._manager = manager

    def gen(self, name: t.Optional[str] = None, update: bool = False) -> None:
        """Generate and store a new nebula X25519 keypair.

        Returns:
            None

        Raises:
            KeyPairExistsError: when keypair already exists and update is False
        """
        manager = self._manager
        # Use default name
        name = name or manager.default_user
        # Create new keypair
        keypair = create_encryption_keypair()
        # Save keypair
        manager.storage.save_keypair(
            name=name,
            keypair=keypair,
            update=update,
        )

    def add_public_key(
        self,
        key: t.Union[str, bytes],
        name: t.Optional[str] = None,
        update: bool = False,
    ) -> None:
        """Import a nebula X25519 public key into store.

        Returns:
            None

        Raises:
            PublicKeyExistsError: when public key already exists and update is False
        """
        manager = self._manager
        # Use default name
        name = name or manager.default_user
        # Parse public key
        public_key = parse_encryption_public_key(key)
        # Save public key
        manager.storage.save_public_key(
            name=name,
            public_key=public_key,
            update=update,
        )

    def add_keypair(
        self,
        key: t.Union[str, bytes],
        name: t.Optional[str] = None,
        update: bool = False,
    ) -> None:
        """Import a nebula X25519 private key into store.

        Returns:
            None

        Raises:
            KeyPairExistsError: when keypair already exists and update is False
        """
        manager = self._manager
        # Use default name
        name = name or manager.default_user
        # Parse keypair
        keypair = parse_encryption_keypair(key)
        # Save keypair
        manager.storage.save_keypair(
            name=name,
            keypair=keypair,
            update=update,
        )

    def show_public_key(
        self,
        name: t.Optional[str] = None,
        raw: bool = False,
        json: bool = False,
    ) -> str:
        """Show public key as string. By default public key is shown in PEM format.

        Arguments:
            name: Name of key to show.
            raw: Show key in raw format (raw bytes displayed as hex) instead of PEM format
            json: Show key in JSON format instead of PEM format

        Raises:
            PublicKeyNotFoundError: When public key is not found
        """
        manager = self._manager
        name = name or manager.default_user
        public_key = manager.storage.get_public_key(name)
        if raw:
            return public_key.to_public_bytes().hex()
        elif json:
            return dumps(
                {
                    "name": name,
                    "nebula_x25519_public_key": public_key.to_public_bytes().hex(),
                },
                indent=2,
            )
        else:
            return public_key.to_public_pem_data().decode("utf-8")

    def show_private_key(
        self,
        name: t.Optional[str] = None,
        raw: bool = False,
        json: bool = False,
    ) -> str:
        """Show private key as string.

        Arguments:
            name: Name of key to show.
            raw: Show key in raw format (raw bytes displayed as hex) instead of PEM format
            json: Show key in JSON format instead of PEM format

        Raises:
            KeyPairNotFoundError: When keypair is not found
        """
        manager = self._manager
        name = name or manager.default_user
        keypair = manager.storage.get_keypair(name)
        if raw:
            return keypair.to_private_bytes().hex()
        elif json:
            return dumps(
                {
                    "name": name,
                    "nebula_x25519_public_key": keypair.to_public_bytes().hex(),
                    "nebula_x25519_private_key": keypair.to_private_bytes().hex(),
                },
                indent=2,
            )
        else:
            return keypair.to_private_pem_data().decode("utf-8")

    def list_keypairs(self) -> t.List[t.Tuple[str, bytes]]:
        """List known keypairs as tuple of name and public bytes"""
        manager = self._manager
        return [
            (name, keypair.public_key.to_public_bytes())
            for name, keypair in dict(manager.storage.find_keypairs()).items()
        ]

    def remove(self, name: t.Optional[str] = None) -> None:
        manager = self._manager
        name = name or manager.default_user
        manager.storage.delete_keypair(name)

    def export_public_keys(self) -> str:
        manager = self._manager
        results: t.List[t.Dict[str, str]] = []
        for name, keypair in manager.storage.find_public_keys():
            results.append(
                {
                    "name": name,
                    "nebula_x25519_public_key": keypair.to_public_bytes().hex(),
                }
            )
        return dumps(results, indent=2)

    def export_keypairs(self) -> str:
        manager = self._manager
        results: t.List[t.Dict[str, str]] = []
        for name, keypair in manager.storage.find_keypairs():
            results.append(
                {
                    "name": name,
                    "nebula_x25519_public_key": keypair.to_public_bytes().hex(),
                    "nebula_x25519_private_key": keypair.to_private_bytes().hex(),
                }
            )
        return dumps(results, indent=2)
