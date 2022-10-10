import typing as t
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import time

from ..utils import parse_duration


@dataclass
class SigningOptions:
    """Options used to sign a certificate.

    The only required fields are `Name` and `Ip`. All other fields have default values.

    Fields:
        `Name`: name assigned to the certificate.
        `Ip`: ip assigned to the certificate.
        `NotAfter`: a string indicating expiration timestamp of certificate.
        `NotBefore`: a string indicating activation timestamp of certificate.
        `Groups`: a list of groups as strings.
        `Subnets`: a list of subnets as strings with CIDR notation.
    """

    Name: str
    Ip: str
    NotAfter: str = "8650h"
    NotBefore: str = "0s"
    Groups: t.List[str] = field(default_factory=list)
    Subnets: t.List[str] = field(default_factory=list)

    def get_activation_timestamp(self) -> datetime:
        """Get activation timestamp as a datetime instance.

        Activation timestamp is available as a string through the `.NotBefore` attribute.
        Use this method to access it as a `datetime.datetime` instead.
        """
        return datetime.fromtimestamp(
            time() + parse_duration(self.NotBefore), tz=timezone.utc
        )

    def get_expiration_timestamp(self) -> datetime:
        """Get expiration timestamp as a datetime instance.

        Expiration timestamp is available as a string through the `.NotAfter` attribute.
        Use this method to access it as a `datetime.datetime` instead.
        """
        return datetime.fromtimestamp(
            time() + parse_duration(self.NotAfter), tz=timezone.utc
        )


@dataclass
class SigningCAOptions:
    """Options used to sign a certificate authority.

    The only required field is `Name`. All other fields have default values.

    Fields:
        `Name`: name assigned to the CA certificate.
        `Ips`: ips constraints assigned to the CA certificate.
        `NotAfter`: a string indicating expiration timestamp of CA certificate.
        `NotBefore`: a string indicating activation timestamp of CA certificate.
        `Groups`: a list of groups as strings. CA certificate cannot sign a certificate with a group not indicated in CA certificate.
        `Subnets`: a list of subnets as strings with CIDR notation. CA certificate cannot sign a certificate with a subnet not indicated in CA certificate.
    """

    Name: str
    Ips: t.List[str] = field(default_factory=list)
    NotAfter: str = "25950h"
    NotBefore: str = "0s"
    Groups: t.List[str] = field(default_factory=list)
    Subnets: t.List[str] = field(default_factory=list)

    def get_activation_timestamp(self) -> datetime:
        """Get activation timestamp as a datetime instance.

        Activation timestamp is available as a string through the `.NotBefore` attribute.
        Use this method to access it as a `datetime.datetime` instead.
        """
        return datetime.fromtimestamp(
            time() + parse_duration(self.NotBefore), tz=timezone.utc
        )

    def get_expiration_timestamp(self) -> datetime:
        """Get expiration timestamp as a datetime instance.

        Expiration timestamp is available as a string through the `.NotAfter` attribute.
        Use this method to access it as a `datetime.datetime` instead.
        """
        return datetime.fromtimestamp(
            time() + parse_duration(self.NotAfter), tz=timezone.utc
        )
