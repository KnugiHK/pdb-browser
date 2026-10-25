#!/usr/bin/env python3
"""
symbols.py - Shared symbol utilities used by both cli.py and gui.py.
"""

import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from pdb_tool import PEParser, PDBReader, SymbolDownloader, Symbol, default_pdb_dir


class SymbolMatcher:
    """Fast prefix + substring lookup over a sorted symbol list."""

    def __init__(self, symbols: list[Symbol]):
        self._by_name = sorted(symbols, key=lambda s: s.name.lower())
        self._names   = [s.name.lower() for s in self._by_name]
        self._map: dict[str, Symbol] = {s.name: s for s in symbols}

    def predict(self, prefix: str) -> Optional[str]:
        """
        Return the best completion for *prefix* (case-insensitive).
        Tries prefix match first, then substring match.
        """
        if not prefix:
            return None
        lp = prefix.lower()

        lo, hi = 0, len(self._names)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._names[mid] < lp:
                lo = mid + 1
            else:
                hi = mid

        if lo < len(self._names) and self._names[lo].startswith(lp):
            return self._by_name[lo].name

        for i, name in enumerate(self._names):
            if lp in name:
                return self._by_name[i].name
        return None

    def exact(self, name: str) -> Optional[Symbol]:
        """Case-sensitive exact lookup."""
        return self._map.get(name)

    def exact_ci(self, name: str) -> Optional[Symbol]:
        """Case-insensitive exact lookup (returns first match)."""
        ln = name.lower()
        for sym_name, sym in self._map.items():
            if sym_name.lower() == ln:
                return sym
        return None


def load_symbols(pe_path: str, output_dir: str, no_download: bool) -> tuple[PEParser, PDBReader]:
    pe_parser = PEParser(pe_path)
    pe_parser.load()
    pdb_info = pe_parser.extract_pdb_info()
    pdb_path = os.path.join(output_dir, pdb_info.pdb_filename)

    if not no_download:
        dl       = SymbolDownloader(output_dir=output_dir)
        pdb_path = dl.download(pdb_info)
    else:
        if not os.path.isfile(pdb_path):
            print(f"[!] PDB not found at {pdb_path} and --no-download was set.",
                  file=sys.stderr)
            sys.exit(1)
        print(f"[*] Using cached PDB: {pdb_path}")

    reader = PDBReader(pdb_path, pe_parser)
    reader.load()
    return pe_parser, reader
