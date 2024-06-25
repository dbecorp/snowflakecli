from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
import os
from pathlib import Path
import shutil
import subprocess

import pyperclip

from cli.core.fs import get_file_contents
from cli.core.logging import logger
from cli.core.constants import (
    SFCLI_DIR,
    SFCLI_KEYPAIR_PUB_NAME,
    SFCLI_KEYPAIR_PRIV_NAME,
    SFCLI_DEFAULT_PRIV_KEY_PATH,
)


def get_private_key_contents(
    private_key_path: Path = SFCLI_DEFAULT_PRIV_KEY_PATH,
) -> str:
    private_key_passphrase = os.environ.get("PRIVATE_KEY_PASSPHRASE")
    if private_key_passphrase:
        private_key_passphrase = private_key_passphrase.encode()
    logger.debug(f"getting private key contents from file {private_key_path}")
    with open(private_key_path, "rb") as key:
        p_key = serialization.load_pem_private_key(
            key.read(),
            password=private_key_passphrase,
            backend=default_backend(),
        )
    return p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


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
            "-nocrypt",  # TODO -> Add encrypted key option
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
    target_directory=SFCLI_DIR, keys=[SFCLI_KEYPAIR_PRIV_NAME, SFCLI_KEYPAIR_PUB_NAME]
) -> None:
    for key in keys:
        src = Path(key)
        dest = Path(target_directory, key)
        shutil.move(src, dest)


def generate_keypair(relocate_to_dir=None, copy_to_clipboard=True) -> None:
    generate_private_key()
    generate_public_key()
    ensure_key_permissions()
    pub_key = get_file_contents(Path(SFCLI_KEYPAIR_PUB_NAME))
    if relocate_to_dir:
        relocate_keys()
    if copy_to_clipboard:
        pyperclip.copy(pub_key)
