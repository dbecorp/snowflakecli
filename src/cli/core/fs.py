import os
from pathlib import Path


def ensure_directory(directory: Path) -> None:
    os.mkdir(directory)


def ensure_file(file: Path) -> None:
    os.mknod(file)


def get_file_contents(file_path: Path) -> str:
    with open(file_path, "r") as f:
        return f.read()
