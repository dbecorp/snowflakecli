import typer

app = typer.Typer()


@app.command()
def identity():
    """Audit the identity security of your Snowflake account"""
    return


@app.command()
def hunt():
    """Threat hunt via Snowflake activity logging"""
    pass
