import typer

app = typer.Typer()


@app.command()
def audit():
    """Audit the security of your Snowflake account"""
    # TODO -> Identities. MFA? OAUTH? Username/passwords in use?
    return


@app.command()
def hunt():
    """Threat hunt via Snowflake activity logging"""
    pass
