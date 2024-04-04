import typer

app = typer.Typer()


@app.command()
def create():
    """Create a Snowflake account"""
    return


@app.command()
def analyze():
    """Analyze Snowflake account usage for potential cost-savings and other optimizations."""
    return
