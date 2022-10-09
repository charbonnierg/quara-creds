import typer

from .gen import gen_cmd
from .list import list_cmd
from .scp import scp_cmd
from .show import show_cmd

app = typer.Typer(
    name="key",
    no_args_is_help=True,
    add_completion=False,
    help="Manager nebula node certificate keys (X25519)",
)


app.command("list")(list_cmd)
app.command("gen")(gen_cmd)
app.command("show")(show_cmd)
app.command("scp")(scp_cmd)
