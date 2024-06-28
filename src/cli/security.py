from typing import Annotated, Optional

import typer

from cli.core.security.hunt import run_threat_hunt

app = typer.Typer(no_args_is_help=True)


@app.command()
def audit():
    """Audit the security of your Snowflake account and recommend alterations"""
    # TODO -> Identities. MFA? OAUTH? Username/passwords in use?
    # Check for single factor user/password-based auth
    # Check for multi-factor auth
    # Ideally check that every user has a key pair set up

    # Check for network policies

    # Check for user-level network policies

    # Check for principal of least privilege
    return


@app.command()
def hunt(
    ctx: typer.Context,
    file: Annotated[
        Optional[str],
        typer.Option(
            "-f",
            help="The hunting definition to use. If no file is passed it will use the hunt definition from the UNC5537 Snowflake breaches",
        ),
    ] = None,
    query_name: Annotated[
        Optional[str],
        typer.Option(
            "-n",
            help="The named hunting query to execute. If no name is passed all hunting queries from the supplied definition will be used",
        ),
    ] = None,
):
    """Threat hunt via Snowflake activity logging"""
    if file:
        run_threat_hunt(
            ctx.obj.cursor, get_file_contents(Path(file)), query_name=query_name
        )
    else:
        run_threat_hunt(ctx.obj.cursor, query_name=query_name)
