import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def create():
    """Create a Snowflake account"""
    return


@app.command()
def list():
    """List Snowflake accounts in your Organization"""
    return


@app.command()
def drop():
    """Drop a Snowflake account"""
    return


@app.command()
def analyze():
    """Analyze Snowflake account usage for cost-savings and other optimizations."""
    return
