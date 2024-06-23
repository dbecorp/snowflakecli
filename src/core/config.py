from pathlib import Path
import os


from core.constants import (
    SFCLI_CONFIG_FILE_PATH,
    SFCLI_KEYPAIR_PUB_NAME,
    SFCLI_KEYPAIR_PRIV_NAME,
    SSH_DIR,
)


DEFAULT_CONFIG_FILE_CONTENTS = f"""
[connections.default]
username = $SNOWFLAKE_USERNAME
accountname = $SNOWFLAKE_ACCOUNTNAME
private_key_path = "{SSH_DIR}/{SFCLI_KEYPAIR_PRIV_NAME}"

[options]
log_file = "/.sfcli/sfcli.log"
log_level = DEBUG
"""


def ensure_config_file() -> None:
    config_path = Path(SFCLI_CONFIG_FILE_PATH)
    if os.path.exists(config_path):
        print("path already exists")
        return
    Path(config_path).parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        f.write(DEFAULT_CONFIG_FILE_CONTENTS)


def configure_sfcli() -> None:
    username = input("What is your Snowflake username? [Required]\n")
    account = input("What is your Snowflake account? [Required]\n")
    sfcli_priv_key_path = input(
        "What is the path to your sfcli private key? (Defaults to ~/.ssh/sfcli.pem)\n"
    )
    pass
