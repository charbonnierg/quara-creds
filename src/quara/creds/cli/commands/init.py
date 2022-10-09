import typing as t
from dataclasses import asdict
from json import dumps, loads
from pathlib import Path

import requests
import typer
from rich.console import Console
from rich.table import Table

from quara.creds.cli.utils import get_manager
from quara.creds.manager.interfaces import Authorities
from quara.creds.manager.settings import NebulaCertManagerSettings

console = Console()


def init_cmd(
    root: t.Optional[str] = typer.Option(
        None, "--root", "-r", help="pync root directory", envvar="PYNC_NEBULA_ROOT"
    ),
    authorities: t.Optional[str] = typer.Option(
        None, "--authorities", "-a", help="Import authorities from a file or an URL"
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite existing config"),
) -> None:
    """Display environment used by pync.

    The "Set" column indicate if variable is configured through environment variable, or using default value.

    The "Set" column is `True` when variable is a default value derived from a user-configured value.
    """
    # Gather root directory
    storage_root = Path(root) if root else Path("~/.nebula")
    # Construct storage config
    config = NebulaCertManagerSettings(
        storage={"files": {"root": storage_root.as_posix()}}
    )
    # Gather authorities
    if authorities is None:
        cert_authorities = Authorities()
    elif authorities.startswith("http://") or authorities.startswith("https://"):
        try:
            cert_authorities = Authorities.from_mapping(
                loads(requests.get(authorities).content)["authorities"]
            )
        except KeyError as exc:
            typer.echo(f"Failed to import authorities: {str(exc)}")
            raise typer.Exit(1)
    else:
        cert_authorities = Authorities.from_json(authorities)
    # Save authorities and config
    storage_root = storage_root.expanduser()
    storage_root.mkdir(exist_ok=True, parents=True)
    config_file = storage_root.joinpath("config.json")
    if config_file.exists() and not force:
        typer.echo(
            f"Configuration file already exist: {config_file.as_posix()}", err=True
        )
        raise typer.Exit(1)
    config_file.write_bytes(dumps(asdict(config), indent=2).encode("utf-8"))
    authorities_file = storage_root.joinpath("authorities.json")
    if authorities_file.exists() and not force:
        typer.echo(
            f"Authorities file already exists: {authorities_file.as_posix()}", err=True
        )
        raise typer.Exit(1)
    authorities_file.write_bytes(
        dumps(
            {
                "authorities": {
                    key: asdict(value) for key, value in cert_authorities.items()
                }
            },
            indent=2,
        ).encode("utf-8")
    )
    # Initialize manager
    manager = get_manager(root=storage_root)
    # Create a new rich table
    table = Table(title="pync nebula environment")
    table.add_column("Setting")
    table.add_column("Value")
    # Add rows to the table
    for key, value in manager.describe_settings().items():
        table.add_row(key, value)
    # Print the table
    console.print(table)
    raise typer.Exit(0)
