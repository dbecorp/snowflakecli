import typer

app = typer.Typer()


@app.command()
def list():
    """List all Snowflake Warehouses"""
    return


@app.command()
def create():
    """Create a Snowflake Warehouse"""
    return


@app.command()
def drop():
    """Drop a Snowflake Warehouse"""
    return


@app.command()
def analyze():
    """[!WIP!] Analyze a Snowflake virtual warehouse for potential cost-savings and other optimizations."""
    return


@app.command()
def optimize():
    """[!WIP!] Analyze actual workloads on a particular warehouse and resize it according to actual needs."""
    return
