"""pync ca show CLI command"""
import typing as t
from json import dumps

import typer
from rich.console import Console
from rich.table import Table

from quara.creds.cli.utils import get_manager

console = Console()


def show_cmd(
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
    name: t.Optional[str] = typer.Option(
        None,
        "--name",
        "-n",
        help="Name of CA to show. All certificates are shown by default.",
    ),
    pem: bool = typer.Option(
        False,
        "--pem",
        help="Display certificates in PEM format",
    ),
    raw: bool = typer.Option(False, "--raw", help="Display raw certificates"),
    json: bool = typer.Option(False, "--json", help="Display JSON certificates"),
) -> None:
    """Describe a ca certificate.

    When --raw option certificate, the raw certificate is printed.
    When --pem option is used, the PEM-encoded certificate is printed.
    """
    manager = get_manager(config, root)
    if name is None:
        authorities = list(manager.authorities)
    else:
        authorities = [name]
    found = False
    json_result: t.List[t.Dict[str, t.Any]] = []
    for authority in authorities:
        try:
            cert = manager.storage.get_signing_certificate(authority=authority)
        except FileNotFoundError:
            continue
        else:
            found = True
        if pem:
            typer.echo(cert.to_pem_data().decode("utf-8"))
            continue
        elif raw:
            typer.echo(cert.to_bytes().hex())
            continue
        elif json:
            data = cert.to_dict()
            signature = data.pop("Signature")
            data["Fingerprint"] = cert.Fingerprint
            data["Signature"] = signature
            json_result.append(data)
            continue
        else:
            table = Table(title="Nebula CA certificate")
            table.add_column("Authority")
            table.add_column(authority)
            for key, value in cert.to_dict().items():
                if key == "IsCA":
                    continue
                elif key == "Signature":
                    continue
                elif key == "Issuer":
                    continue
                elif key == "NotAfter":
                    key = "Expiration"
                    value = cert.get_expiration_timestamp().isoformat()
                elif key == "NotBefore":
                    key = "Activation"
                    value = cert.get_activation_timestamp().isoformat()
                table.add_row(key, str(value))
            table.add_row("Fingerprint", cert.Fingerprint)
            table.add_section()
            table.add_row("Signature", cert.Signature.hex())
            console.print(table)
    if json_result:
        console.print(dumps(json_result, indent=2))
    if not found:
        typer.echo("CA certificate not found", err=True)
        raise typer.Exit(1)

    raise typer.Exit(0)
