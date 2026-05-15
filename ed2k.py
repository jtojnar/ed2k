#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Jan Tojnar
# SPDX-License-Identifier: MIT


from Crypto.Hash import MD4
from collections.abc import Iterator
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Sequence
from urllib.parse import quote
import argparse
import sys


ED2K_CHUNK_SIZE = 9500 * 1024


@dataclass
class Ed2kHash:
    """Result of ed2k hashing"""

    name: str
    size: int
    root_hash: str

    def ed2k_uri(self) -> str:
        """Formats the hash as an ed2k URI."""
        return f"ed2k://|file|{quote(self.name)}|{self.size}|{self.root_hash}|/"


def chunks(path: Path, chunk_size: int) -> Iterator[bytes]:
    """Splits file into chunks of `chunk_size` bytes."""
    with path.open("rb") as f:
        for chunk in iter(partial(f.read, chunk_size), b""):
            yield chunk


def md4(data: bytes) -> bytes:
    """Calculates MD4 checksum of `data`."""
    h = MD4.new()
    h.update(data)
    return h.digest()


def ed2k_root_hash(ed2k_chunks: Iterator[bytes]) -> str:
    """Calculates eD2k root hash (hash of the hash list) for the chunks."""
    h = MD4.new()

    for chunk in ed2k_chunks:
        h.update(md4(chunk))

    return h.hexdigest()


def ed2k(path: Path) -> Ed2kHash:
    """Calculates an eD2k hash for given file."""
    name = path.name
    size = path.stat().st_size

    if size <= ED2K_CHUNK_SIZE:
        root_hash = md4(path.read_bytes()).hex()
    else:
        ed2k_chunks = chunks(path, ED2K_CHUNK_SIZE)
        root_hash = ed2k_root_hash(ed2k_chunks)

    return Ed2kHash(name, size, root_hash)


def hash_and_print(files: Sequence[Path]) -> bool:
    """Calculates hash for each file and outputs the result as URI."""
    all_okay = True

    for file in files:
        try:
            print(ed2k(file).ed2k_uri())
        except Exception as e:
            all_okay = False
            print(f"Failed to hash {file}: {e}", file=sys.stderr)

    return all_okay


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Produces ed2k hashes of files",
    )

    parser.add_argument(
        "files",
        metavar="FILE",
        nargs="+",
        type=Path,
        help="Files to hash",
    )

    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None | str:
    args = parse_args(argv)

    if not hash_and_print(args.files):
        return "Could not hash some files"

    return None


if __name__ == "__main__":
    raise SystemExit(main())
