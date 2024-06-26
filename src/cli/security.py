import typer


app = typer.Typer(no_args_is_help=True)


@app.command()
def audit(
    file: Annotated[
        Optional[str],
        typer.Option(
            "-f",
            help="The audit definition to use. If no file is passed it will use the default audit definition.",
        ),
    ] = None,
):
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
            help="The hunting definition to use. If no file is passed it will use the hunt definition from the UNC5537 breaches",
        ),
    ] = None,
):
    """Threat hunt via Snowflake activity logging"""

    # What should be hunted?
    # - Suspicious user activity
    # - Bulk exfiltration
    # - https://github.com/Permiso-io-tools/YetiHunter/blob/main/queries/queries.json
    pass
