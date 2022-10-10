import typer

from .list import list_cmd
from .show import show_cmd
from .sign import sign_cmd

app = typer.Typer(
    name="ca",
    no_args_is_help=True,
    add_completion=False,
    help="Manage nebula CA certificates",
)

app.command("show")(show_cmd)
app.command("list")(list_cmd)
app.command("sign")(sign_cmd)
