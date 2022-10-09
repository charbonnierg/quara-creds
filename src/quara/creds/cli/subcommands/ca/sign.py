"""pync nebula ca create CLI command"""
import typing as t
from json import loads
from pathlib import Path

import typer

from quara.creds.nebula import SigningCAOptions, sign_ca


def sign_cmd(
    name: str = typer.Option(
        ...,
        "--name",
        "-n",
        help="name of the certificate authority as indicated in CA certificates",
    ),
    duration: str = typer.Option(
        "26280h",
        "--duration",
        "-d",
        help=(
            "amount of time issued CA certificate should be valid for. "
            'Valid time units are seconds: "s", minutes: "m", hours: "h"'
        ),
    ),
    groups: t.Optional[str] = typer.Option(
        None,
        "--groups",
        "-g",
        help="comma separated list of groups. This will limit which groups subordinate certs can use",
    ),
    ips: t.Optional[str] = typer.Option(
        None,
        "--ips",
        "-i",
        help=(
            "comma separated list of ip and network in CIDR notation. "
            "This will limit which ip addresses and networks subordinate certs can use"
        ),
    ),
    subnets: t.Optional[str] = typer.Option(
        None,
        "--subnets",
        "-s",
        help=(
            "comma separated list of ip and network in CIDR notation. "
            "This will limit which subnet addresses and networks subordinate certs can use"
        ),
    ),
    config_file: t.Optional[str] = typer.Option(
        None,
        "--config-file",
        "-f",
        help=(
            "path to a JSON configuration file. "
            "Options found within file will be used to generate the certificate."
        ),
    ),
    out_key: t.Optional[str] = typer.Option(
        None,
        "--out-key",
        help="Path to file where CA private key will be written",
    ),
    out_pub: t.Optional[str] = typer.Option(
        None,
        "--out-pub",
        help="Path to file where CA public key will be written",
    ),
    out_ca: t.Optional[str] = typer.Option(
        None,
        "--out-ca",
        help="Path to file where CA certificate will be written",
    ),
) -> None:
    """Create a CA certificate."""
    # if config is not None:
    #     manager = NebulaCertManager.from_config_file(config)
    # else:
    #     manager = NebulaCertManager.from_root(root)
    if config_file:
        try:
            data = loads(Path(config_file).read_bytes())
            options = SigningCAOptions(**data)
        except Exception as exc:
            typer.echo(f"Invalid signing options: {str(exc)}", err=True)
            raise typer.Exit(1)
    else:
        options = SigningCAOptions(
            Name=name,
            Ips=ips.split(",") if ips else [],
            NotAfter=duration,
            Groups=groups.split(",") if groups else [],
            Subnets=subnets.split(",") if subnets else [],
        )
    keypair, ca = sign_ca(options)
    if out_key is None:
        out_key = f"{name}.key"
    keypair.write_private_key(out_key)
    if out_pub:
        keypair.write_public_key(out_pub)
    if out_ca is None:
        out_ca = f"{name}.crt"
    ca.write_pem_file(out_ca)
