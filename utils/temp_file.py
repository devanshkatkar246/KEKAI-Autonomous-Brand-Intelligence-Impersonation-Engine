import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import List, Generator
from fastapi import UploadFile

# Ensure /tmp working directory exists (handles Windows & Linux)
TMP_DIR = Path("/tmp")
try:
    TMP_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    # Fallback to current working directory /tmp if system root /tmp is disallowed
    TMP_DIR = Path("./tmp").resolve()
    TMP_DIR.mkdir(parents=True, exist_ok=True)


@contextmanager
def save_temp_file(upload_file: UploadFile) -> Generator[str, None, None]:
    """
    Saves an uploaded FastAPI file into /tmp working dir, yields the temp file path,
    and guarantees file cleanup upon context exit.
    """
    ext = Path(upload_file.filename).suffix if upload_file.filename else ".tmp"
    filename = f"logo_{uuid.uuid4().hex}{ext}"
    temp_path = TMP_DIR / filename

    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)
        yield str(temp_path)
    finally:
        if temp_path.exists():
            try:
                os.remove(temp_path)
            except Exception:
                pass


@contextmanager
def save_temp_files(upload_files: List[UploadFile]) -> Generator[List[str], None, None]:
    """
    Saves multiple uploaded FastAPI files into /tmp working dir, yields list of file paths,
    and guarantees file cleanup upon context exit.
    """
    saved_paths: List[Path] = []
    try:
        paths = []
        for file in upload_files:
            ext = Path(file.filename).suffix if file.filename else ".tmp"
            filename = f"logo_{uuid.uuid4().hex}{ext}"
            temp_path = TMP_DIR / filename
            with open(temp_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            saved_paths.append(temp_path)
            paths.append(str(temp_path))
        yield paths
    finally:
        for path in saved_paths:
            if path.exists():
                try:
                    os.remove(path)
                except Exception:
                    pass
