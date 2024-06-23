import subprocess
import os
import shutil
from pathlib import Path


import typer
import pyperclip

from core.fs import get_file_contents
from core.logging import logger
from core.constants import SSH_DIR, SFCLI_KEYPAIR_PUB_NAME, SFCLI_KEYPAIR_PRIV_NAME


app = typer.Typer(no_args_is_help=True)


def generate_private_key() -> None:
    key = subprocess.Popen(
        [
            "openssl",
            "genrsa",
            "2048",
        ],
        stdout=subprocess.PIPE,
    )
    key.wait()
    out = subprocess.Popen(
        [
            "openssl",
            "pkcs8",
            "-topk8",
            "-inform",
            "PEM",
            "-out",
            SFCLI_KEYPAIR_PRIV_NAME,
            "-nocrypt",
        ],
        stdin=key.stdout,
    )
    out.wait()


def generate_public_key() -> None:
    key = subprocess.Popen(
        [
            "openssl",
            "rsa",
            "-in",
            SFCLI_KEYPAIR_PRIV_NAME,
            "-pubout",
            "-out",
            SFCLI_KEYPAIR_PUB_NAME,
        ],
    )
    key.wait()


def ensure_key_permissions(
    priv_key=SFCLI_KEYPAIR_PRIV_NAME, pub_key=SFCLI_KEYPAIR_PUB_NAME
) -> None:
    """Make sure keys are appropriately privileged, instead of simply saying "you're on you're own" """
    os.chmod(priv_key, 0o600)
    os.chmod(pub_key, 0o644)


def relocate_keys(
    target_directory=SSH_DIR, keys=[SFCLI_KEYPAIR_PRIV_NAME, SFCLI_KEYPAIR_PUB_NAME]
) -> None:
    for key in keys:
        src = Path(key)
        dest = Path(target_directory, key)
        logger.debug(f"Relocating key from {src} to {dest}")
        shutil.move(src, dest)


def generate_keypair(relocate_to_dir=None, copy_to_clipboard=True) -> None:
    generate_private_key()
    generate_public_key()
    ensure_key_permissions()
    pub_key = get_file_contents(Path(SFCLI_KEYPAIR_PUB_NAME))
    print(f"\n\nPublic key generated:\n{pub_key}")
    if relocate_to_dir:
        relocate_keys()
    if copy_to_clipboard:
        print("\n\nPublic key contents have been copied to your clipboard!")
        pyperclip.copy(pub_key)


@app.command()
def generate(
    destination_dir=SSH_DIR,
):  # TODO -> add destination dir cli flag, add pre-existing keys check (and don't regen if one already exists)
    """Generate a public/private key pair, ensure privileges, move to ssh directory, and copy the contents of the public key to the clipboard"""
    generate_keypair(relocate_to_dir=SSH_DIR, copy_to_clipboard=True)
    return


@app.command()
def rotate():
    """Rotate the existing public/private key pair"""
    generate_keypair(relocate_to_dir=SSH_DIR, copy_to_clipboard=True)
