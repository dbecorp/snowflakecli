import os
from pathlib import Path


# Configuration
USR_HOME_DIR = os.path.expanduser("~")
SFCLI_DIR = Path(USR_HOME_DIR, ".sfcli")


# Key Pair Generation
SSH_DIR = Path(USR_HOME_DIR, ".ssh")
SFCLI_CONFIG_FILE_PATH = Path(USR_HOME_DIR, ".sfcli", "config")
SFCLI_KEYPAIR_PRIV_NAME = "sfcli.p8"
SFCLI_DEFAULT_PRIV_KEY_PATH = Path(SFCLI_DIR, SFCLI_KEYPAIR_PRIV_NAME)
SFCLI_KEYPAIR_PUB_NAME = "sfcli.pub"
SFCLI_DEFAULT_PUB_KEY_PATH = Path(SFCLI_DIR, SFCLI_KEYPAIR_PUB_NAME)


# General
SFCLI = "snowflakecli"
