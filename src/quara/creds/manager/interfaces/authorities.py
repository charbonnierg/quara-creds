import typing as t
from dataclasses import dataclass
from json import loads
from pathlib import Path

from quara.creds.nebula import SigningKeyPair


class Lighthouses(t.Dict[str, t.Dict[str, t.List[str]]]):
    """A mapping of nebula lighthouses IP address and public addresses:

    ```json
    {
        "<nebula_ip>": [<public_ip>, <public_ip>]
    }
    ```json
    """

    @classmethod
    def from_mapping(
        cls, data: t.Mapping[str, t.Mapping[str, t.Iterable[str]]]
    ) -> "Lighthouses":
        """Create Lighthouses from a mapping."""
        return cls(
            {key: {k: list(v) for k, v in value.items()} for key, value in data.items()}
        )


@dataclass
class Authority:
    """Metadata about a certificate authority.

    Arguments:
        name: can be different from name indicated within CA certificate.
        certificate: must be a valid URL pointing to CA certificate.
        keystore: must be a valid URI pointing to CA keystore.
        lighthouses: A mapping of lighthouses used to generate nebula configurations
    """

    name: str
    certificate: str
    keystore: str
    lighthouses: Lighthouses

    @classmethod
    def from_mapping(cls, data: t.Mapping[str, t.Any]) -> "Authority":
        """Create a new Authority from a mapping."""
        values = dict(data)
        lighthouses = values.pop("lighthouses", {})
        values["lighthouses"] = Lighthouses(lighthouses)
        return cls(**values)

    def get_signing_keypair(self) -> SigningKeyPair:
        """Get signing keypair"""
        from quara.creds.manager.adapters.keystores import create_store

        return create_store(self.keystore).get_ca_key(self.name)


class Authorities(t.Dict[str, Authority]):
    """A list of authorities"""

    @classmethod
    def from_mapping(cls, data: t.Mapping[str, t.Mapping[str, str]]) -> "Authorities":
        """Parse authorities from a mapping."""
        return cls({key: Authority.from_mapping(value) for key, value in data.items()})

    @classmethod
    def from_json(cls, filepath: t.Union[str, Path]) -> "Authorities":
        """Parse authorities from a JSON file."""
        data = loads(Path(filepath).expanduser().read_bytes())
        return cls.from_mapping(data["authorities"])
