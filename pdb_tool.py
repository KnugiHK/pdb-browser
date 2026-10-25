#!/usr/bin/env python3
"""
pdb_tool.py - Extract PDB GUID/Age from PE files, download symbols from
the Microsoft Symbol Server, and parse all public symbols with their RVAs.

Usage:
    python pdb_tool.py <path_to_exe_or_dll>
"""

import argparse
import struct
import sys
import os
import tempfile
import requests
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


def default_pdb_dir() -> str:
    """Return the OS temp directory as the default PDB download location."""
    return tempfile.gettempdir()

import pefile


@dataclass
class PdbInfo:
    """PDB debug information extracted from a PE file."""
    guid: str           # 32-char hex, uppercase, no dashes
    age: int
    pdb_filename: str   # basename only, e.g. "ntoskrnl.pdb"
    guid_age: str       # GUID+Age string used in the symbol server URL


@dataclass
class Symbol:
    """A single public symbol with its RVA."""
    name: str
    offset: int     # RVA (relative virtual address)
    segment: int    # 1-based PE section index

    def __repr__(self) -> str:
        return f"Symbol(name={self.name!r}, rva=0x{self.offset:08X}, seg={self.segment})"


class PEParser:
    """Parses a PE (EXE/DLL) and extracts PDB debug info + section headers."""

    RSDS_SIGNATURE = b"RSDS"

    def __init__(self, pe_path: str):
        self.pe_path = pe_path
        self._pe: Optional[pefile.PE] = None
        # (VirtualAddress, VirtualSize) per section, 0-indexed.
        # Use sections[segment - 1] for 1-based segment indices.
        self.sections: list[tuple[int, int]] = []

    def load(self) -> None:
        print(f"[*] Loading PE file: {self.pe_path}")
        self._pe = pefile.PE(self.pe_path)
        self._load_sections()

    def _load_sections(self) -> None:
        self.sections = []
        for sec in self._pe.sections:
            self.sections.append((sec.VirtualAddress, sec.Misc_VirtualSize))
        print(f"    PE sections   : {len(self.sections)}")

    def extract_pdb_info(self) -> PdbInfo:
        """Walk the Debug Directory for a CodeView RSDS entry and return PdbInfo."""
        if self._pe is None:
            raise RuntimeError("PE not loaded. Call load() first.")
        if not hasattr(self._pe, "DIRECTORY_ENTRY_DEBUG"):
            raise ValueError("No debug directory found in PE file.")

        for dbg_entry in self._pe.DIRECTORY_ENTRY_DEBUG:
            if dbg_entry.struct.Type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                continue

            raw_offset = dbg_entry.struct.PointerToRawData
            raw_size   = dbg_entry.struct.SizeOfData
            raw_data   = self._pe.__data__[raw_offset: raw_offset + raw_size]

            if len(raw_data) < 24 or raw_data[:4] != self.RSDS_SIGNATURE:
                continue

            # RSDS layout:
            #   4 bytes  "RSDS"
            #  16 bytes  GUID  (Data1=LE DWORD, Data2=LE WORD, Data3=LE WORD, Data4=8 bytes BE)
            #   4 bytes  Age   (LE DWORD)
            #   N bytes  PDB path (null-terminated UTF-8)
            guid_bytes = raw_data[4:20]
            age        = struct.unpack_from("<I", raw_data, 20)[0]
            pdb_path   = raw_data[24:].split(b"\x00")[0].decode("utf-8", errors="replace")

            d1 = struct.unpack_from("<I", guid_bytes, 0)[0]
            d2 = struct.unpack_from("<H", guid_bytes, 4)[0]
            d3 = struct.unpack_from("<H", guid_bytes, 6)[0]
            d4 = guid_bytes[8:16]

            guid_str     = f"{d1:08X}{d2:04X}{d3:04X}" + d4.hex().upper()
            pdb_filename = Path(pdb_path).name
            guid_age     = f"{guid_str}{age:X}"

            info = PdbInfo(guid=guid_str, age=age, pdb_filename=pdb_filename, guid_age=guid_age)
            print(f"[+] PDB filename : {pdb_filename}")
            print(f"[+] GUID         : {guid_str}")
            print(f"[+] Age          : {age}")
            print(f"[+] GUID+Age     : {guid_age}")
            return info

        raise ValueError("No RSDS CodeView debug entry found in PE file.")

    def seg_offset_to_rva(self, segment: int, offset: int) -> int:
        """Convert a 1-based segment index + intra-section offset to an RVA."""
        if segment < 1 or segment > len(self.sections):
            return offset
        return self.sections[segment - 1][0] + offset


class SymbolDownloader:
    """Downloads a PDB file from the Microsoft Symbol Server."""

    SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or default_pdb_dir()

    def build_url(self, pdb_info: PdbInfo) -> str:
        return (
            f"{self.SYMBOL_SERVER}"
            f"/{pdb_info.pdb_filename}"
            f"/{pdb_info.guid_age}"
            f"/{pdb_info.pdb_filename}"
        )

    def download(self, pdb_info: PdbInfo) -> str:
        """Download the PDB and return the local path. Skips if already cached."""
        url        = self.build_url(pdb_info)
        local_path = os.path.join(self.output_dir, pdb_info.pdb_filename)

        if os.path.exists(local_path):
            print(f"[*] PDB already cached: {local_path}")
            return local_path

        print(f"[*] Downloading PDB from:\n    {url}")
        headers  = {"User-Agent": "Microsoft-Symbol-Server/10.0.10522.521"}
        response = requests.get(url, headers=headers, stream=True, timeout=120)
        if response.status_code != 200:
            raise RuntimeError(
                f"Symbol server returned HTTP {response.status_code} for:\n  {url}"
            )

        total      = int(response.headers.get("content-length", 0))
        downloaded = 0
        with open(local_path, "wb") as fh:
            for chunk in response.iter_content(chunk_size=65536):
                fh.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 // total
                    print(f"\r    {downloaded:,} / {total:,} bytes ({pct}%)", end="", flush=True)
        print()
        print(f"[+] Saved to: {local_path}")
        return local_path


class MSFReader:
    """
    Reads a PDB 7.0 / MSF 7.00 container.

    The file is divided into fixed-size pages. A stream is a logical sequence
    of pages. The stream directory maps stream indices to page lists and sizes.
    """

    MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

    def __init__(self, path: str):
        self.path = path
        self._data: bytes = b""
        self.page_size: int = 0
        self.num_streams: int = 0
        self._stream_sizes: list[int] = []
        self._stream_page_lists: list[list[int]] = []

    def load(self) -> None:
        with open(self.path, "rb") as fh:
            self._data = fh.read()
        self._parse_superblock()
        self._parse_stream_directory()

    def get_stream(self, index: int) -> bytes:
        """Return the raw bytes of stream *index*."""
        if index >= self.num_streams:
            raise IndexError(f"Stream {index} out of range (total: {self.num_streams})")
        size  = self._stream_sizes[index]
        pages = self._stream_page_lists[index]
        if size == 0xFFFFFFFF or size == 0:
            return b""
        chunks    = []
        remaining = size
        for page_num in pages:
            offset = page_num * self.page_size
            take   = min(self.page_size, remaining)
            chunks.append(self._data[offset: offset + take])
            remaining -= take
            if remaining <= 0:
                break
        return b"".join(chunks)

    def _u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self._data, offset)[0]

    def _parse_superblock(self) -> None:
        if self._data[:32] != self.MSF7_MAGIC:
            raise ValueError("Not a valid PDB 7.0 file (bad magic).")

        # Superblock layout (all LE):
        #  0  32  Magic
        # 32   4  BlockSize
        # 36   4  FreeBlockMapBlock  (ignored)
        # 40   4  NumBlocks
        # 44   4  NumDirectoryBytes
        # 48   4  Unknown
        # 52   4  BlockMapAddr
        self.page_size = self._u32(32)
        dir_size       = self._u32(44)
        block_map_addr = self._u32(52)

        num_dir_pages    = (dir_size + self.page_size - 1) // self.page_size
        block_map_offset = block_map_addr * self.page_size
        dir_page_indices = [
            self._u32(block_map_offset + i * 4) for i in range(num_dir_pages)
        ]

        dir_bytes = b""
        remaining = dir_size
        for page_idx in dir_page_indices:
            offset = page_idx * self.page_size
            take   = min(self.page_size, remaining)
            dir_bytes += self._data[offset: offset + take]
            remaining -= take
        self._dir_bytes = dir_bytes

    def _parse_stream_directory(self) -> None:
        pos = 0
        self.num_streams = struct.unpack_from("<I", self._dir_bytes, pos)[0]
        pos += 4

        self._stream_sizes = []
        for _ in range(self.num_streams):
            self._stream_sizes.append(struct.unpack_from("<I", self._dir_bytes, pos)[0])
            pos += 4

        self._stream_page_lists = []
        for sz in self._stream_sizes:
            if sz == 0xFFFFFFFF or sz == 0:
                self._stream_page_lists.append([])
                continue
            num_pages = (sz + self.page_size - 1) // self.page_size
            pages = [
                struct.unpack_from("<I", self._dir_bytes, pos + j * 4)[0]
                for j in range(num_pages)
            ]
            pos += num_pages * 4
            self._stream_page_lists.append(pages)


class PDBInfoStream:
    """Parses PDB Stream 1 (PDB Info / Named Stream Map)."""

    def __init__(self, data: bytes):
        self._data = data
        self.version: int = 0
        self.age: int = 0
        self.guid: str = ""

    def parse(self) -> None:
        if len(self._data) < 28:
            raise ValueError("PDB info stream too short.")
        self.version = struct.unpack_from("<I", self._data, 0)[0]
        self.age     = struct.unpack_from("<I", self._data, 8)[0]
        guid_bytes   = self._data[12:28]
        d1 = struct.unpack_from("<I", guid_bytes, 0)[0]
        d2 = struct.unpack_from("<H", guid_bytes, 4)[0]
        d3 = struct.unpack_from("<H", guid_bytes, 6)[0]
        d4 = guid_bytes[8:16]
        self.guid = f"{d1:08X}{d2:04X}{d3:04X}" + d4.hex().upper()


class DBIStream:
    """
    Parses PDB Stream 3 (DBI / Debug Info stream).

    Extracts stream indices for the global symbol hash, public symbol hash,
    and symbol records streams.
    """

    def __init__(self, data: bytes):
        self._data = data
        self.global_stream_index: int = -1
        self.public_stream_index: int = -1
        self.sym_record_stream: int   = -1

    def parse(self) -> None:
        if len(self._data) < 64:
            raise ValueError("DBI stream too short.")

        # DBI fixed header (64 bytes):
        #  0  4  VersionSignature  (0xFFFFFFFF)
        #  4  4  VersionHeader
        #  8  4  Age
        # 12  2  GlobalStreamIndex
        # 14  2  BuildNumber
        # 16  2  PublicStreamIndex
        # 18  2  PdbDllVersion
        # 20  2  SymRecordStream
        # 22  2  PdbDllRbld
        # 24  4  ModInfoSize
        # 28  4  SectionContributionSize
        # 32  4  SectionMapSize
        # 36  4  SourceInfoSize
        # 40  4  TypeServerMapSize
        # 44  4  MFCTypeServerIndex
        # 48  4  OptionalDbgHeaderSize
        # 52  4  ECSubstreamSize
        # 56  2  Flags
        # 58  2  Machine
        # 60  4  Padding
        self.global_stream_index = struct.unpack_from("<H", self._data, 12)[0]
        self.public_stream_index = struct.unpack_from("<H", self._data, 16)[0]
        self.sym_record_stream   = struct.unpack_from("<H", self._data, 20)[0]


class PublicSymbolStream:
    """
    Parses the Public Symbol Stream (index from DBI).

    Header (28 bytes) is followed by:
      - a symbol hash sub-stream (sym_hash_size bytes)
      - an address map (addr_map_size bytes): uint32 offsets into the symbol
        records stream, one per symbol

    We walk the address map to enumerate every S_PUB32 record.
    """

    S_PUB32    = 0x110E
    S_PUB32_ST = 0x1009

    def __init__(self, pub_data: bytes, sym_record_data: bytes):
        self._pub  = pub_data
        self._syms = sym_record_data

    def parse(self) -> list[Symbol]:
        """Return all public symbols (unsorted; caller sorts by RVA)."""
        symbols: list[Symbol] = []

        # Public stream header (28 bytes):
        #  0  4  SymHash   – size of the hash sub-stream in bytes
        #  4  4  AddrMap   – size of the address map in bytes
        #  8  4  NumThunks
        # 12  4  SizeOfThunk
        # 16  2  ISectThunkTable
        # 18  2  padding
        # 20  4  OffThunkTable
        # 24  4  NumSects
        if len(self._pub) < 28:
            return symbols

        sym_hash_size   = struct.unpack_from("<I", self._pub, 0)[0]
        addr_map_size   = struct.unpack_from("<I", self._pub, 4)[0]
        addr_map_offset = 28 + sym_hash_size

        if addr_map_offset + addr_map_size > len(self._pub):
            return symbols

        num_addrs = addr_map_size // 4
        for i in range(num_addrs):
            rec_offset = struct.unpack_from("<I", self._pub, addr_map_offset + i * 4)[0]
            sym = self._parse_sym_record(rec_offset)
            if sym is not None:
                symbols.append(sym)
        return symbols

    def _parse_sym_record(self, offset: int) -> Optional[Symbol]:
        """
        Parse one CodeView symbol record at *offset* in the symbol records stream.

        Record layout:
          2  Length  (of the rest of the record, not including these 2 bytes)
          2  Kind    (symbol type)
          N  payload

        S_PUB32 payload:
          4  Flags   DWORD
          4  Offset  DWORD  (offset within the segment)
          2  Seg     WORD   (1-based PE section index)
          N  Name    null-terminated string
        """
        data = self._syms
        if offset + 4 > len(data):
            return None
        kind = struct.unpack_from("<H", data, offset + 2)[0]
        if kind not in (self.S_PUB32, self.S_PUB32_ST):
            return None
        payload = offset + 4  # skip Length + Kind
        if payload + 10 > len(data):
            return None
        sym_offset  = struct.unpack_from("<I", data, payload + 4)[0]
        sym_segment = struct.unpack_from("<H", data, payload + 8)[0]
        name_start  = payload + 10
        name_end    = data.index(b"\x00", name_start)
        name        = data[name_start:name_end].decode("utf-8", errors="replace")
        return Symbol(name=name, offset=sym_offset, segment=sym_segment)


class PDBReader:
    """
    Orchestrates MSF loading, stream parsing, and symbol extraction.

    Requires a PEParser (already loaded) to convert segment:offset pairs
    to RVAs using the PE's own section table.
    """

    def __init__(self, pdb_path: str, pe_parser: PEParser):
        self.pdb_path  = pdb_path
        self._pe       = pe_parser
        self._msf: Optional[MSFReader] = None
        self.symbols: list[Symbol] = []

    def load(self) -> None:
        """Load the PDB and extract all public symbols as RVAs."""
        print(f"[*] Parsing PDB: {self.pdb_path}")
        self._msf = MSFReader(self.pdb_path)
        self._msf.load()
        print(f"    MSF page size : {self._msf.page_size} bytes")
        print(f"    Total streams : {self._msf.num_streams}")

        info = PDBInfoStream(self._msf.get_stream(1))
        info.parse()
        print(f"    PDB GUID      : {info.guid}")
        print(f"    PDB Age       : {info.age}")

        dbi = DBIStream(self._msf.get_stream(3))
        dbi.parse()
        print(f"    Global stream : {dbi.global_stream_index}")
        print(f"    Public stream : {dbi.public_stream_index}")
        print(f"    Sym records   : {dbi.sym_record_stream}")

        sym_record_data = self._msf.get_stream(dbi.sym_record_stream)
        pub_data        = self._msf.get_stream(dbi.public_stream_index)
        raw_symbols     = PublicSymbolStream(pub_data, sym_record_data).parse()

        self.symbols = []
        for sym in raw_symbols:
            rva = self._pe.seg_offset_to_rva(sym.segment, sym.offset)
            self.symbols.append(Symbol(name=sym.name, offset=rva, segment=sym.segment))
        self.symbols.sort(key=lambda s: s.offset)
        print(f"[+] Extracted {len(self.symbols):,} public symbols.")

    def find(self, name: str) -> Optional[Symbol]:
        """Case-sensitive lookup by symbol name."""
        for sym in self.symbols:
            if sym.name == name:
                return sym
        return None

    def print_symbols(self, limit: Optional[int] = None) -> None:
        """Print symbols to stdout, optionally capped at *limit* entries."""
        total = len(self.symbols)
        shown = self.symbols[:limit] if limit else self.symbols
        cap   = f", showing first {limit}" if limit and limit < total else ""
        print(f"\n{'='*72}")
        print(f"  PUBLIC SYMBOLS  ({total:,} total{cap})")
        print(f"{'='*72}")
        print(f"  {'RVA':>10}  {'Seg':>4}  Name")
        print(f"  {'-'*10}  {'-'*4}  {'-'*52}")
        for sym in shown:
            print(f"  0x{sym.offset:08X}  {sym.segment:>4}  {sym.name}")
        if limit and limit < total:
            print(f"  ... and {total - limit:,} more symbols.")
        print(f"{'='*72}\n")

    def save_symbols(self, output_path: str) -> None:
        """Save all symbols to a TSV file (RVA, Segment, Name)."""
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("RVA\tSegment\tName\n")
            for sym in self.symbols:
                fh.write(f"0x{sym.offset:08X}\t{sym.segment}\t{sym.name}\n")
        print(f"[+] Symbols saved to: {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract PDB GUID/Age from a PE file, download symbols from "
            "the Microsoft Symbol Server, and list all public symbols with RVAs."
        )
    )
    parser.add_argument("pe_file", help="Path to the EXE or DLL file.")
    parser.add_argument(
        "--output-dir", "-o", default=None,
        help=(
            "Directory to save the downloaded PDB. "
            f"Defaults to the system temp folder ({default_pdb_dir()})."
        ),
    )
    parser.add_argument(
        "--save-to-cwd", action="store_true",
        help="Save the downloaded PDB to the current working directory instead of temp.",
    )
    parser.add_argument("--save-symbols", "-s", metavar="FILE",
                        help="Save the full symbol list to a TSV file.")
    parser.add_argument("--limit", "-n", type=int, default=50,
                        help="Symbols to print to console (default: 50; 0 = all).")
    parser.add_argument("--no-download", action="store_true",
                        help="Skip downloading; use an already-cached PDB.")
    parser.add_argument("--find", metavar="SYMBOL",
                        help="Look up a specific symbol by name and print its RVA.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not os.path.isfile(args.pe_file):
        print(f"[!] File not found: {args.pe_file}", file=sys.stderr)
        sys.exit(1)

    # Resolve output directory: explicit > --save-to-cwd > temp
    if args.output_dir:
        output_dir = args.output_dir
    elif args.save_to_cwd:
        output_dir = os.getcwd()
    else:
        output_dir = default_pdb_dir()
    print(f"[*] PDB output dir : {output_dir}")

    pe_parser = PEParser(args.pe_file)
    pe_parser.load()
    pdb_info = pe_parser.extract_pdb_info()

    pdb_path = os.path.join(output_dir, pdb_info.pdb_filename)
    if not args.no_download:
        downloader = SymbolDownloader(output_dir=output_dir)
        pdb_path   = downloader.download(pdb_info)
    else:
        if not os.path.isfile(pdb_path):
            print(f"[!] PDB not found at {pdb_path} and --no-download was set.", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Using cached PDB: {pdb_path}")

    reader = PDBReader(pdb_path, pe_parser)
    reader.load()

    if args.find:
        sym = reader.find(args.find)
        if sym:
            print(f"\n[+] Found: {sym.name}  RVA=0x{sym.offset:08X}  segment={sym.segment}")
        else:
            print(f"\n[!] Symbol not found: {args.find!r}")

    limit = args.limit if args.limit > 0 else None
    reader.print_symbols(limit=limit)

    if args.save_symbols:
        reader.save_symbols(args.save_symbols)


if __name__ == "__main__":
    main()
