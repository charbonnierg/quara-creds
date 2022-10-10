import typer

from .list import list_cmd

app = typer.Typer(
    name="authorities",
    no_args_is_help=True,
    add_completion=False,
    help="Manage pync authorities",
)

app.command("list")(list_cmd)
