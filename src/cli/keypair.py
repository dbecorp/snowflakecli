import typer

from core.util.key import generate_keypair
from core.constants import SFCLI_DIR


app = typer.Typer(no_args_is_help=True)


@app.command()
def generate(
    destination_dir=SFCLI_DIR,
):  # TODO -> add destination dir cli flag, add pre-existing keys check (and don't regen if one already exists)
    """Generate a public/private key pair, ensure privileges, move to ssh directory, and copy the contents of the public key to the clipboard"""
    generate_keypair(relocate_to_dir=SFCLI_DIR, copy_to_clipboard=True)
    return


@app.command()
def rotate():
    """Rotate the existing public/private key pair"""
    generate_keypair(relocate_to_dir=SFCLI_DIR, copy_to_clipboard=True)
