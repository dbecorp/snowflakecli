import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def question():
    """Ask the Snowflakecli LLM a question about your Snowflake resources"""
    return
