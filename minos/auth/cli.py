from pathlib import (
    Path,
)
from typing import (
    Optional,
)

import typer

from .config import (
    AuthConfig,
)
from .launchers import (
    EntrypointLauncher,
)
from .service import (
    AuthRestService,
)

app = typer.Typer()


@app.command("start")
def start(
    file_path: Optional[Path] = typer.Argument(
        "config.yml", help="Auth service configuration file.", envvar="MINOS_AUTH_SERVICE_CONFIG_FILE_PATH"
    )
):  # pragma: no cover
    """Start Auth services."""

    try:
        config = AuthConfig(file_path)
    except Exception as exc:
        typer.echo(f"Error loading config: {exc!r}")
        raise typer.Exit(code=1)

    services = (AuthRestService(address=config.rest.host, port=config.rest.port, config=config),)
    try:
        EntrypointLauncher(config=config, services=services).launch()
    except Exception as exc:
        typer.echo(f"Error launching Auth service: {exc!r}")
        raise typer.Exit(code=1)

    typer.echo("Auth service is up and running!\n")


@app.command("status")
def status():
    """Get the Auth status."""
    raise NotImplementedError


@app.command("stop")
def stop():
    """Stop the Auth Gateway."""
    raise NotImplementedError


def main():  # pragma: no cover
    """CLI's main function."""
    app()
