import typer

app = typer.Typer()


@app.command()
def create():
    """Create a Snowflake Warehouse"""
    return


@app.command()
def analyze():
    """Analyze a Snowflake virtual warehouse for potential cost-savings and other optimizations."""
    return


@app.command()
def optimize():
    """Analyze actual workloads on a particular warehouse and resize it according to actual needs."""
    return
