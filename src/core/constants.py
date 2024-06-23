import os
from pathlib import Path


USR_HOME_DIR = os.path.expanduser("~")
SSH_DIR = Path(USR_HOME_DIR, ".ssh")
SFCLI_DIR = Path(USR_HOME_DIR, ".sfcli")
SFCLI_CONFIG_FILE_PATH = Path(USR_HOME_DIR, ".sfcli", "config")
SFCLI_KEYPAIR_PRIV_NAME = "sfcli.pem"
SFCLI_KEYPAIR_PUB_NAME = "sfcli.pub"
