import typer

app = typer.Typer()


@app.command()
def cli():
    """Configure Snowflake CLI"""
    # TODO -> ensure directory exists and snowflakecli config file is present
    return
