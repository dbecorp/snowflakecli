import os


def ensure_directory(directory: str) -> None:
    os.mkdirs(directory, exist_ok=True)


def ensure_file(file: str) -> None:
    os.mknod(file)


def get_file_contents(file_path: str) -> str:
    with open(file_path, "r") as f:
        return f.read()
