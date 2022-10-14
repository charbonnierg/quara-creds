import typing as t
from dataclasses import asdict
from json import dumps
from time import time

from quara.creds.manager.errors import SigningRequestNotFoundError
from quara.creds.manager.interfaces.signing_requests import SigningRequest
from quara.creds.nebula.api.functional import (
    create_signing_options,
    verify_signing_options,
)
from quara.creds.nebula.interfaces import SigningOptions

if t.TYPE_CHECKING:
    from quara.creds.manager.manager import NebulaCertManager


class ManagedSigningRequests:
    def __init__(self, manager: "NebulaCertManager") -> None:
        self._manager = manager

    def add(
        self,
        options: SigningOptions,
        name: t.Optional[str] = None,
        authorities: t.Optional[str] = None,
        update: bool = False,
    ) -> None:
        """Import a signing request from signing options"""
        manager = self._manager
        name = name or manager.default_user
        authorities = self._manager.storage.get_authorities(authorities=authorities)
        for authority in authorities:
            ca_crt = self._manager.storage.get_signing_certificate(authority=authority)
            verify_signing_options(ca_crt=ca_crt, options=options)
            self._manager.storage.save_signing_request(
                authority=authority, options=options, update=update
            )

    def list(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> t.List[SigningRequest]:
        manager = self._manager
        signing_requests: t.List[SigningRequest] = []
        for _, signing_request in manager.storage.find_signing_requests(
            authorities=authorities, names=names
        ):
            signing_requests.append(signing_request)
        return signing_requests

    def export(
        self,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        names: t.Union[str, t.Iterable[str], None] = None,
    ) -> str:
        """Export signing requests in JSON format"""
        manager = self._manager
        json_result: t.List[t.Dict[str, t.Any]] = list()
        for _, signing_request in manager.storage.find_signing_requests(
            authorities=authorities, names=names
        ):
            json_result.append(
                {
                    "authority": signing_request.authority,
                    "user": signing_request.options.Name,
                    "options": asdict(signing_request.options),
                }
            )
        return dumps(json_result, indent=2)

    def remove(
        self,
        name: t.Optional[str] = None,
        authorities: t.Union[str, t.Iterable[str], None] = None,
    ) -> None:
        manager = self._manager
        name = name or manager.default_user
        manager.storage.delete_signing_requests(name=name, authorities=authorities)

    def update(
        self,
        name: t.Optional[str] = None,
        authorities: t.Union[str, t.Iterable[str], None] = None,
        duration: t.Optional[str] = None,
        activation: t.Optional[str] = None,
        groups: t.Optional[str] = None,
        ip: t.Optional[str] = None,
        subnets: t.Optional[str] = None,
    ) -> None:
        manager = self._manager
        name = name or manager.default_user
        authorities = manager.storage.get_authorities(authorities=authorities)
        for authority in authorities:
            ca_crt = manager.storage.get_signing_certificate(authority)
            # Fetch csr if it exists
            try:
                csr = manager.storage.get_signing_request(authority, name)
            except SigningRequestNotFoundError:
                signing_options = None
            else:
                signing_options = csr.options
            # Check that an IP address is provided
            if signing_options is None and ip is None:
                raise ValueError("An IP address must be provided")
            # Check if two different IPs are provided
            if signing_options and ip:
                if signing_options.Ip != ip:
                    signing_options.Ip = ip
            # Create signing options when necessary
            if signing_options is None:
                if duration == "max":
                    duration = f"{int(ca_crt.NotAfter - time()) - 604800}s"
                signing_options = create_signing_options(
                    name=name,
                    ip=ip,
                    groups=groups,
                    subnets=subnets,
                    duration=duration,
                    activation=activation,
                )
            else:
                # Check if an update is needed
                if groups:
                    group_list = groups.split(",")
                    if not all(group in signing_options.Groups for group in group_list):
                        for group in group_list:
                            if group not in signing_options.Groups:
                                signing_options.Groups.append(group)

                # Check if an update is needed
                if subnets and not all(
                    subnet in signing_options.Subnets for subnet in subnets
                ):
                    for subnet in subnets:
                        if subnet not in signing_options.Subnets:
                            signing_options.Subnets.append(subnet)
                # Check if an update is needed
                if duration:
                    if duration == "max":
                        duration = f"{int(ca_crt.NotAfter - time()) - 604800}s"
                    signing_options.NotAfter = duration
                # Chec if an update is needed
                if activation:
                    signing_options.NotBefore = activation
            # Verify signing options
            verify_signing_options(options=signing_options, ca_crt=ca_crt)
            # Save signing options
            manager.storage.save_signing_request(
                authority=authority, options=signing_options, update=True
            )
