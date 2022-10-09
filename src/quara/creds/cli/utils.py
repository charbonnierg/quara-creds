import typing as t

import typer

from quara.creds.manager import NebulaCertManager


def get_manager(
    config: t.Optional[str] = None, root: t.Optional[str] = None
) -> NebulaCertManager:
    try:
        if config is not None:
            return NebulaCertManager.from_config_file(config)
        else:
            return NebulaCertManager.from_root(root)
    except FileNotFoundError:
        typer.echo("Error: cannot find configuration file")
        raise typer.Exit(1)
