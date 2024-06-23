import typer


app = typer.Typer(no_args_is_help=True)


@app.command()
def audit():
    """Audit the security of your Snowflake account"""
    # TODO -> Identities. MFA? OAUTH? Username/passwords in use?
    return


@app.command()
def hunt():
    """Threat hunt via Snowflake activity logging"""
    pass
