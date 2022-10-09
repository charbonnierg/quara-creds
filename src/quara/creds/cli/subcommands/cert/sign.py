"""pync nebula ca add CLI command"""
import typing as t
from json import loads
from pathlib import Path
from time import time

import typer
from rich.console import Console
from rich.table import Table

from quara.creds.cli.utils import get_manager
from quara.creds.nebula import (
    EncryptionKeyPair,
    InvalidSigningOptionError,
    SigningOptions,
    sign_cert,
    verify_certificate,
    verify_signing_options,
)

console = Console()


def sign_cmd(
    root: t.Optional[str] = typer.Option(
        None, "--root", "-r", help="Nebula root directory", envvar="PYNC_NEBULA_ROOT"
    ),
    config: t.Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="pync configuration file",
        envvar="PYNC_NEBULA_CONFIG",
    ),
    authority: str = typer.Option(
        None, "--ca", help="Name of CA used to sign the certificate"
    ),
    name: t.Optional[str] = typer.Option(
        None, "--name", "-n", help="name of the certificate"
    ),
    duration: str = typer.Option(
        None,
        "--duration",
        "-d",
        help=(
            "amount of time the certificate should be valid for. "
            'Valid time units are seconds: "s", minutes: "m", hours: "h"'
        ),
    ),
    groups: t.Optional[str] = typer.Option(
        None,
        "--groups",
        "-g",
        help="comma separated list of groups. This will limit which groups subordinate certs can use",
    ),
    ip: t.Optional[str] = typer.Option(
        None,
        "--ip",
        "-i",
        help=("IP address and network in CIDR notation. "),
    ),
    subnets: t.Optional[str] = typer.Option(
        None,
        "--subnets",
        "-s",
        help=(
            "comma separated list of ip and network in CIDR notation this certificate can serve for"
        ),
    ),
    csr_file: t.Optional[str] = typer.Option(
        None,
        "--csr-file",
        "-f",
        help=(
            "path to a JSON signing request. "
            "Options found within file will be used to generate the certificate."
        ),
    ),
    update: bool = typer.Option(
        False, help="Update certificate signing request before issuing certificate"
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite certificat if it already exists, even if certificate is still valid",
    ),
) -> None:
    """Create a certificate."""
    manager = get_manager(config, root)

    name = name or manager.default_user
    # Gather list of authorities used to issue certificates
    if authority is None:
        authorities = list(manager.authorities)
    else:
        authorities = [authority]
    # Try to load certificate keypair
    try:
        keypair = manager.storage.get_keypair(name)
    except FileNotFoundError:
        keypair = EncryptionKeyPair()
        manager.storage.save_keypair(name, keypair)
    for authority in authorities:
        # Try to load CA
        try:
            ca_crt = manager.storage.get_signing_certificate(authority)
        except FileNotFoundError:
            typer.echo(f"Unknown authority: {authority}")
            raise typer.Exit(1)

        # Try to load certificate
        try:
            crt = manager.storage.get_certificate(authority, name)
        except FileNotFoundError:
            pass
        # If certificate is found
        else:
            # Verify certificate
            try:
                verify_certificate(ca_crt, crt)
            except Exception:
                pass
            # If certificate is valid
            else:
                if not force:
                    typer.echo(f"Error: certificate already exists: {name}", err=True)
                    raise typer.Exit(1)

        # Fetch signing options
        if csr_file:
            csr_data = loads(Path(csr_file).read_bytes())
            csr_data["Name"] = name
            try:
                signing_options = SigningOptions(**csr_data)
            except Exception:
                typer.echo(f"Invalid signing options: {csr_file}", err=True)
                raise typer.Exit(1)
            try:
                verify_signing_options(signing_options=signing_options, ca_crt=ca_crt)
            except InvalidSigningOptionError as exc:
                typer.echo(f"Invalid signing options: {exc.msg}", err=True)
                raise typer.Exit(1)
        else:
            # Fetch csr if it exists
            try:
                signing_options = manager.storage.get_signing_request(authority, name)
            except FileNotFoundError:
                signing_options = None
            # Check that an IP address is provided
            if signing_options is None and ip is None:
                typer.echo("An IP address must be provided", err=True)
                raise typer.Exit(1)
            # Check if two different IPs are provided
            if signing_options and ip:
                if signing_options.Ip != ip:
                    if not update:
                        typer.echo(
                            "IP address provided as command line argument differ from signing request options"
                        )
                        typer.echo(f"    argument value: {ip}")
                        typer.echo(f"    csr value:      {signing_options.Ip}")
                        raise typer.Exit(1)
                    signing_options.Ip = ip
            # Create signing options when necessary
            if signing_options is None:
                if duration == "max":
                    duration = f"{int(ca_crt.NotAfter - time()) - 604800}s"
                signing_options = SigningOptions(
                    Name=name,
                    Ip=ip,
                    Groups=groups.split(",") if groups else [],
                    Subnets=subnets.split(",") if subnets else [],
                    NotAfter=duration,
                )
            else:
                # Check if an update is needed
                if groups:
                    group_list = groups.split(",")
                    if not all(group in signing_options.Groups for group in group_list):
                        if not update:
                            typer.echo(
                                "Some groups are not present within current certificate request. Use the --update option."
                            )
                            raise typer.Exit(1)
                        for group in group_list:
                            if group not in signing_options.Groups:
                                signing_options.Groups.append(group)

                # Check if an update is needed
                if subnets and not all(
                    subnet in signing_options.Subnets for subnet in subnets
                ):
                    if not update:
                        typer.echo(
                            "Some subnets are not present within current certificate request. Use the --update option."
                        )
                        raise typer.Exit(1)
                    for subnet in subnets:
                        if subnet not in signing_options.Subnets:
                            signing_options.Subnets.append(subnet)

                # Check if an update is needed
                if duration:
                    if duration == "max":
                        duration = f"{int(ca_crt.NotAfter - time()) - 604800}s"
                    if duration != signing_options.NotAfter and not update:
                        typer.echo(
                            f"Invalid duration: {duration}. Expected: {signing_options.NotAfter}"
                        )
                        raise typer.Exit(1)
                    else:
                        signing_options.NotAfter = duration
            # Verify signing options
            try:
                verify_signing_options(options=signing_options, ca_crt=ca_crt)
            except InvalidSigningOptionError as exc:
                typer.echo(f"Invalid signing options: {exc.msg}")
                raise typer.Exit(1)
            # Save signing options
            manager.storage.save_signing_request(
                authority=authority, options=signing_options
            )

        # Fetch CA key
        ca_key = manager.storage.get_authority(authority).get_signing_keypair()

        # Then sign certificate
        crt = sign_cert(
            ca_crt=ca_crt,
            ca_key=ca_key,
            public_key=keypair,
            options=signing_options,
        )

        # Validate certificate to make sure we did not mess up somewhere
        verify_certificate(ca_crt=ca_crt, crt=crt)

        manager.storage.save_certificate(authority=authority, certificate=crt)

        table = Table(title="Nebula certificate")
        table.add_column("Field")
        table.add_column("Value")
        for key, value in crt.to_dict().items():
            if key == "IsCA":
                continue
            elif key == "Signature":
                continue
            elif key == "NotAfter":
                key = "Expiration"
                value = crt.get_expiration_timestamp().isoformat()
            elif key == "NotBefore":
                key = "Activation"
                value = crt.get_activation_timestamp().isoformat()
            table.add_row(key, str(value))
        table.add_section()
        table.add_row("Signature", crt.Signature.hex())
        console.print(table)

    raise typer.Exit(0)
