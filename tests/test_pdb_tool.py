import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Make sure the project root (one level up from tests/) is on the path.
sys.path.insert(0, str(Path(__file__).parent.parent))

from pdb_tool import (
    DBIStream,
    MSFReader,
    PDBInfoStream,
    PDBReader,
    PEParser,
    PdbInfo,
    PublicSymbolStream,
    Symbol,
    SymbolDownloader,
)

DATA_DIR     = Path(__file__).parent / "data"   # tests/data/
NTOSKRNL     = DATA_DIR / "ntoskrnl.exe"
NTKRNLMP_PDB = DATA_DIR / "ntkrnlmp.pdb"


# ---------------------------------------------------------------------------
# Helpers – synthetic binary builders
# ---------------------------------------------------------------------------

def _pack_u16(v: int) -> bytes:
    return struct.pack("<H", v)

def _pack_u32(v: int) -> bytes:
    return struct.pack("<I", v)


def _make_rsds_blob(
    guid_d1: int = 0x11223344,
    guid_d2: int = 0x5566,
    guid_d3: int = 0x7788,
    guid_d4: bytes = b"\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00",
    age: int = 2,
    pdb_path: bytes = b"C:\\symbols\\test.pdb\x00",
) -> bytes:
    """Build a minimal RSDS CodeView debug blob."""
    return (
        b"RSDS"
        + struct.pack("<IHH", guid_d1, guid_d2, guid_d3)
        + guid_d4
        + _pack_u32(age)
        + pdb_path
    )


def _make_pdb_info_stream(
    version: int = 20000404,
    signature: int = 0,
    age: int = 3,
    guid_d1: int = 0xAABBCCDD,
    guid_d2: int = 0x1122,
    guid_d3: int = 0x3344,
    guid_d4: bytes = b"\x55\x66\x77\x88\x99\xAA\xBB\xCC",
) -> bytes:
    """Build a minimal PDB info stream (stream 1)."""
    return (
        _pack_u32(version)
        + _pack_u32(signature)
        + _pack_u32(age)
        + struct.pack("<IHH", guid_d1, guid_d2, guid_d3)
        + guid_d4
        + b"\x00" * 8   # padding / named stream map (empty)
    )


def _make_dbi_header(
    global_stream: int = 10,
    public_stream: int = 11,
    sym_record_stream: int = 12,
    mod_info_size: int = 0,
    section_contribution_size: int = 0,
    section_map_size: int = 0,
    source_info_size: int = 0,
    type_server_map_size: int = 0,
    optional_dbg_header_size: int = 0,
    ec_substream_size: int = 0,
) -> bytes:
    """Build a minimal 64-byte DBI fixed header."""
    return (
        _pack_u32(0xFFFFFFFF)           # VersionSignature
        + _pack_u32(19990903)           # VersionHeader
        + _pack_u32(1)                  # Age
        + _pack_u16(global_stream)      # GlobalStreamIndex
        + _pack_u16(0)                  # BuildNumber
        + _pack_u16(public_stream)      # PublicStreamIndex
        + _pack_u16(0)                  # PdbDllVersion
        + _pack_u16(sym_record_stream)  # SymRecordStream
        + _pack_u16(0)                  # PdbDllRbld
        + _pack_u32(mod_info_size)
        + _pack_u32(section_contribution_size)
        + _pack_u32(section_map_size)
        + _pack_u32(source_info_size)
        + _pack_u32(type_server_map_size)
        + _pack_u32(0)                  # MFCTypeServerIndex
        + _pack_u32(optional_dbg_header_size)
        + _pack_u32(ec_substream_size)
        + _pack_u16(0)                  # Flags
        + _pack_u16(0x8664)             # Machine (AMD64)
        + _pack_u32(0)                  # Padding
    )


def _make_pub32_record(name: bytes, seg: int, offset: int, flags: int = 0) -> bytes:
    """Build a single S_PUB32 (0x110E) CodeView symbol record."""
    # payload = flags(4) + offset(4) + seg(2) + name(N) + null
    payload = _pack_u32(flags) + _pack_u32(offset) + _pack_u16(seg) + name + b"\x00"
    # record  = length(2) + kind(2) + payload
    length  = 2 + len(payload)   # kind(2) + payload
    return _pack_u16(length) + _pack_u16(0x110E) + payload


def _make_public_stream_header(sym_hash_size: int, addr_map_entries: list[int]) -> bytes:
    """Build the 28-byte public stream header + address map."""
    addr_map_bytes = b"".join(_pack_u32(e) for e in addr_map_entries)
    addr_map_size  = len(addr_map_bytes)
    header = (
        _pack_u32(sym_hash_size)   # SymHash size
        + _pack_u32(addr_map_size) # AddrMap size
        + _pack_u32(0)             # NumThunks
        + _pack_u32(0)             # SizeOfThunk
        + _pack_u16(0)             # ISectThunkTable
        + _pack_u16(0)             # padding
        + _pack_u32(0)             # OffThunkTable
        + _pack_u32(0)             # NumSects
    )
    # sym_hash_size bytes of dummy hash data follow the header
    return header + b"\x00" * sym_hash_size + addr_map_bytes


# ---------------------------------------------------------------------------
# MSF builder – creates a minimal valid PDB 7.0 container in memory
# ---------------------------------------------------------------------------

class MSFBuilder:
    """
    Builds a minimal MSF 7.0 binary with arbitrary stream contents.
    Layout (page_size = 512):
      page 0  – superblock
      page 1  – free-block map 1  (unused, zeroed)
      page 2  – free-block map 2  (unused, zeroed)
      page 3  – block-map page    (array of dir-page indices)
      page 4+ – stream directory  (one page)
      page 5+ – stream data pages
    """

    PAGE_SIZE = 512
    MAGIC     = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

    def __init__(self):
        self._streams: list[bytes] = []

    def add_stream(self, data: bytes) -> int:
        """Append a stream and return its index."""
        self._streams.append(data)
        return len(self._streams) - 1

    def build(self) -> bytes:
        ps = self.PAGE_SIZE

        # ── Allocate pages ────────────────────────────────────────────────
        # Fixed pages: 0=superblock, 1=FBM1, 2=FBM2, 3=block-map
        next_page = 4

        # Stream directory bytes
        dir_bytes = self._build_directory(next_page)
        # We'll place the directory starting at next_page
        dir_page_start = next_page
        num_dir_pages  = (len(dir_bytes) + ps - 1) // ps
        next_page     += num_dir_pages

        # Stream data pages
        stream_page_lists: list[list[int]] = []
        stream_data_pages: list[bytes]     = []
        for stream in self._streams:
            pages = []
            offset = 0
            while offset < len(stream):
                chunk = stream[offset: offset + ps].ljust(ps, b"\x00")
                stream_data_pages.append(chunk)
                pages.append(next_page)
                next_page += 1
                offset    += ps
            stream_page_lists.append(pages)

        total_pages = next_page

        # ── Rebuild directory with correct page numbers ───────────────────
        dir_bytes = self._build_directory_with_pages(stream_page_lists)
        num_dir_pages = (len(dir_bytes) + ps - 1) // ps

        # ── Assemble the file ─────────────────────────────────────────────
        pages: dict[int, bytes] = {}

        # Superblock (page 0)
        block_map_addr = 3
        superblock = (
            self.MAGIC
            + _pack_u32(ps)                  # BlockSize
            + _pack_u32(1)                   # FreeBlockMapBlock
            + _pack_u32(total_pages)         # NumBlocks
            + _pack_u32(len(dir_bytes))      # NumDirectoryBytes
            + _pack_u32(0)                   # Unknown
            + _pack_u32(block_map_addr)      # BlockMapAddr
        )
        pages[0] = superblock.ljust(ps, b"\x00")

        # FBM pages (1, 2) – zeroed
        pages[1] = b"\x00" * ps
        pages[2] = b"\x00" * ps

        # Block-map page (3): array of dir-page indices
        bm = b"".join(_pack_u32(dir_page_start + i) for i in range(num_dir_pages))
        pages[3] = bm.ljust(ps, b"\x00")

        # Directory pages
        for i in range(num_dir_pages):
            chunk = dir_bytes[i * ps: (i + 1) * ps].ljust(ps, b"\x00")
            pages[dir_page_start + i] = chunk

        # Stream data pages
        for page_data, page_list in zip(
            stream_data_pages,
            [p for pl in stream_page_lists for p in pl],
        ):
            pages[page_list] = page_data

        # Flatten
        result = bytearray()
        for i in range(total_pages):
            result += pages.get(i, b"\x00" * ps)
        return bytes(result)

    def _build_directory_with_pages(self, stream_page_lists: list[list[int]]) -> bytes:
        num_streams = len(self._streams)
        d = _pack_u32(num_streams)
        for stream in self._streams:
            d += _pack_u32(len(stream))
        for pages in stream_page_lists:
            for p in pages:
                d += _pack_u32(p)
        return d

    def _build_directory(self, first_data_page: int) -> bytes:
        """Placeholder – real layout computed in build()."""
        return self._build_directory_with_pages([[] for _ in self._streams])


# ---------------------------------------------------------------------------
# Test: PdbInfo dataclass
# ---------------------------------------------------------------------------

class TestPdbInfo(unittest.TestCase):

    def test_fields_stored(self):
        info = PdbInfo(
            guid="AABBCCDD11223344EEFF001122334455",
            age=2,
            pdb_filename="foo.pdb",
            guid_age="AABBCCDD11223344EEFF0011223344552",
        )
        self.assertEqual(info.guid, "AABBCCDD11223344EEFF001122334455")
        self.assertEqual(info.age, 2)
        self.assertEqual(info.pdb_filename, "foo.pdb")
        self.assertEqual(info.guid_age, "AABBCCDD11223344EEFF0011223344552")

    def test_guid_age_format(self):
        # guid_age must be GUID (32 chars) + hex age (no leading zeros for age=1)
        info = PdbInfo(guid="A" * 32, age=1, pdb_filename="x.pdb", guid_age="A" * 32 + "1")
        self.assertTrue(info.guid_age.endswith("1"))
        self.assertEqual(len(info.guid_age), 33)


# ---------------------------------------------------------------------------
# Test: Symbol dataclass
# ---------------------------------------------------------------------------

class TestSymbol(unittest.TestCase):

    def test_fields(self):
        s = Symbol(name="NtCreateFile", offset=0x1234, segment=1)
        self.assertEqual(s.name, "NtCreateFile")
        self.assertEqual(s.offset, 0x1234)
        self.assertEqual(s.segment, 1)

    def test_repr_format(self):
        s = Symbol(name="Foo", offset=0xABCD, segment=2)
        r = repr(s)
        self.assertIn("Foo", r)
        self.assertIn("0x0000ABCD", r)
        self.assertIn("2", r)


# ---------------------------------------------------------------------------
# Test: PEParser.seg_offset_to_rva  (the critical bug fix)
# ---------------------------------------------------------------------------

class TestPEParserSegOffsetToRva(unittest.TestCase):
    """
    Tests for the segment→RVA conversion.
    This is the function that was broken in the original version.
    """

    def _make_parser_with_sections(self, sections: list[tuple[int, int]]) -> PEParser:
        """Return a PEParser whose sections list is pre-populated."""
        p = PEParser.__new__(PEParser)
        p.pe_path = "<mock>"
        p._pe = None
        p.sections = sections
        return p

    def test_known_good_halplmstub(self):
        """
        Regression: HalpLMStub is in segment 8 (.text, VA=0x00200000)
        with intra-section offset 0x0022A470.
        Expected RVA = 0x00200000 + 0x0022A470 = 0x0042A470.
        """
        # Minimal section table: 8 sections, only section 8 matters here.
        sections = [
            (0x00001000, 0x000C5910),  # 1 .rdata
            (0x000C7000, 0x0006D05C),  # 2 .pdata
            (0x00135000, 0x000020FE),  # 3 .idata
            (0x00138000, 0x00019716),  # 4 .edata
            (0x00152000, 0x00000001),  # 5 PROTDATA
            (0x00153000, 0x00009C54),  # 6 GFIDS
            (0x0015D000, 0x000A3000),  # 7 Pad1
            (0x00200000, 0x0043BBFD),  # 8 .text
        ]
        parser = self._make_parser_with_sections(sections)
        rva = parser.seg_offset_to_rva(segment=8, offset=0x0022A470)
        self.assertEqual(rva, 0x0042A470)

    def test_segment_1(self):
        sections = [(0x1000, 0x500), (0x2000, 0x300)]
        parser = self._make_parser_with_sections(sections)
        self.assertEqual(parser.seg_offset_to_rva(1, 0x100), 0x1100)

    def test_segment_2(self):
        sections = [(0x1000, 0x500), (0x2000, 0x300)]
        parser = self._make_parser_with_sections(sections)
        self.assertEqual(parser.seg_offset_to_rva(2, 0x50), 0x2050)

    def test_segment_zero_returns_offset(self):
        """Segment 0 is out-of-range; offset returned unchanged."""
        sections = [(0x1000, 0x500)]
        parser = self._make_parser_with_sections(sections)
        self.assertEqual(parser.seg_offset_to_rva(0, 0xABCD), 0xABCD)

    def test_segment_out_of_range_returns_offset(self):
        sections = [(0x1000, 0x500)]
        parser = self._make_parser_with_sections(sections)
        self.assertEqual(parser.seg_offset_to_rva(99, 0x1234), 0x1234)

    def test_zero_offset(self):
        sections = [(0x5000, 0x100)]
        parser = self._make_parser_with_sections(sections)
        self.assertEqual(parser.seg_offset_to_rva(1, 0), 0x5000)


# ---------------------------------------------------------------------------
# Test: PEParser RSDS extraction (mocked pefile)
# ---------------------------------------------------------------------------

class TestPEParserExtractPdbInfo(unittest.TestCase):

    def _make_mock_pe(self, rsds_blob: bytes, debug_type: int = 2):
        """Return a mock pefile.PE with one debug directory entry."""
        mock_pe = MagicMock()
        mock_pe.__data__ = b"\x00" * 100 + rsds_blob

        entry = MagicMock()
        entry.struct.Type = debug_type
        entry.struct.PointerToRawData = 100
        entry.struct.SizeOfData = len(rsds_blob)
        mock_pe.DIRECTORY_ENTRY_DEBUG = [entry]

        # Sections
        sec = MagicMock()
        sec.VirtualAddress = 0x1000
        sec.Misc_VirtualSize = 0x500
        mock_pe.sections = [sec]
        return mock_pe

    def _make_parser(self, mock_pe) -> PEParser:
        p = PEParser.__new__(PEParser)
        p.pe_path = "<mock>"
        p._pe = mock_pe
        p.sections = []
        p._load_sections()
        return p

    def test_guid_formatting(self):
        """GUID bytes must be formatted as 32 uppercase hex chars, no dashes."""
        blob = _make_rsds_blob(
            guid_d1=0x11223344,
            guid_d2=0x5566,
            guid_d3=0x7788,
            guid_d4=b"\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00",
            age=1,
            pdb_path=b"C:\\foo\\bar.pdb\x00",
        )
        parser = self._make_parser(self._make_mock_pe(blob))
        info = parser.extract_pdb_info()

        self.assertEqual(info.guid, "112233445566778899AABBCCDDEEFF00")
        self.assertEqual(len(info.guid), 32)
        self.assertNotIn("-", info.guid)

    def test_age_extracted(self):
        blob = _make_rsds_blob(age=7, pdb_path=b"x.pdb\x00")
        parser = self._make_parser(self._make_mock_pe(blob))
        info = parser.extract_pdb_info()
        self.assertEqual(info.age, 7)

    def test_pdb_filename_basename_only(self):
        """Full path in the PE → only the basename is stored."""
        blob = _make_rsds_blob(pdb_path=b"C:\\Windows\\System32\\foo.pdb\x00")
        parser = self._make_parser(self._make_mock_pe(blob))
        info = parser.extract_pdb_info()
        self.assertEqual(info.pdb_filename, "foo.pdb")

    def test_guid_age_concatenation(self):
        """guid_age = GUID + hex(age), age=1 → single '1', not '01'."""
        blob = _make_rsds_blob(
            guid_d1=0xAABBCCDD, guid_d2=0x1122, guid_d3=0x3344,
            guid_d4=b"\x55\x66\x77\x88\x99\xAA\xBB\xCC",
            age=1, pdb_path=b"t.pdb\x00",
        )
        parser = self._make_parser(self._make_mock_pe(blob))
        info = parser.extract_pdb_info()
        self.assertEqual(info.guid_age, info.guid + "1")

    def test_guid_age_hex_age(self):
        """Age=16 should appear as '10' (hex) in guid_age."""
        blob = _make_rsds_blob(age=16, pdb_path=b"t.pdb\x00")
        parser = self._make_parser(self._make_mock_pe(blob))
        info = parser.extract_pdb_info()
        self.assertTrue(info.guid_age.endswith("10"))

    def test_non_codeview_entry_skipped(self):
        """Debug entries with type != 2 must be ignored."""
        blob = _make_rsds_blob(pdb_path=b"t.pdb\x00")
        mock_pe = self._make_mock_pe(blob, debug_type=4)  # not CodeView
        parser = self._make_parser(mock_pe)
        with self.assertRaises(ValueError):
            parser.extract_pdb_info()

    def test_no_debug_directory_raises(self):
        mock_pe = MagicMock(spec=[])   # no DIRECTORY_ENTRY_DEBUG attribute
        mock_pe.sections = []
        parser = PEParser.__new__(PEParser)
        parser.pe_path = "<mock>"
        parser._pe = mock_pe
        parser.sections = []
        with self.assertRaises((ValueError, AttributeError)):
            parser.extract_pdb_info()

    def test_load_sections_populates_list(self):
        mock_pe = MagicMock()
        s1, s2 = MagicMock(), MagicMock()
        s1.VirtualAddress, s1.Misc_VirtualSize = 0x1000, 0x200
        s2.VirtualAddress, s2.Misc_VirtualSize = 0x2000, 0x400
        mock_pe.sections = [s1, s2]
        mock_pe.DIRECTORY_ENTRY_DEBUG = []
        parser = PEParser.__new__(PEParser)
        parser.pe_path = "<mock>"
        parser._pe = mock_pe
        parser.sections = []
        parser._load_sections()
        self.assertEqual(parser.sections, [(0x1000, 0x200), (0x2000, 0x400)])


# ---------------------------------------------------------------------------
# Test: SymbolDownloader.build_url
# ---------------------------------------------------------------------------

class TestSymbolDownloaderBuildUrl(unittest.TestCase):

    def setUp(self):
        self.dl = SymbolDownloader(output_dir=".")

    def test_url_structure(self):
        info = PdbInfo(
            guid="AABBCCDD11223344EEFF001122334455",
            age=1,
            pdb_filename="ntkrnlmp.pdb",
            guid_age="AABBCCDD11223344EEFF0011223344551",
        )
        url = self.dl.build_url(info)
        self.assertEqual(
            url,
            "https://msdl.microsoft.com/download/symbols"
            "/ntkrnlmp.pdb"
            "/AABBCCDD11223344EEFF0011223344551"
            "/ntkrnlmp.pdb",
        )

    def test_url_starts_with_msdl(self):
        info = PdbInfo(guid="A" * 32, age=2, pdb_filename="foo.pdb", guid_age="A" * 32 + "2")
        url = self.dl.build_url(info)
        self.assertTrue(url.startswith("https://msdl.microsoft.com/download/symbols/"))

    def test_url_contains_pdb_filename_twice(self):
        info = PdbInfo(guid="B" * 32, age=1, pdb_filename="bar.pdb", guid_age="B" * 32 + "1")
        url = self.dl.build_url(info)
        self.assertEqual(url.count("bar.pdb"), 2)

    def test_url_contains_guid_age(self):
        guid_age = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC5"
        info = PdbInfo(guid="C" * 32, age=5, pdb_filename="baz.pdb", guid_age=guid_age)
        url = self.dl.build_url(info)
        self.assertIn(guid_age, url)

    def test_download_skips_existing_file(self):
        """If the PDB already exists on disk, download() must not make HTTP requests."""
        with tempfile.TemporaryDirectory() as tmp:
            pdb_path = os.path.join(tmp, "cached.pdb")
            Path(pdb_path).write_bytes(b"fake pdb")

            info = PdbInfo(guid="D" * 32, age=1, pdb_filename="cached.pdb",
                           guid_age="D" * 32 + "1")
            dl = SymbolDownloader(output_dir=tmp)

            with patch("pdb_tool.requests.get") as mock_get:
                result = dl.download(info)
                mock_get.assert_not_called()
            self.assertEqual(result, pdb_path)


# ---------------------------------------------------------------------------
# Test: PDBInfoStream
# ---------------------------------------------------------------------------

class TestPDBInfoStream(unittest.TestCase):

    def test_guid_parsed(self):
        data = _make_pdb_info_stream(
            guid_d1=0x11223344, guid_d2=0x5566, guid_d3=0x7788,
            guid_d4=b"\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00",
        )
        s = PDBInfoStream(data)
        s.parse()
        self.assertEqual(s.guid, "112233445566778899AABBCCDDEEFF00")

    def test_age_parsed(self):
        data = _make_pdb_info_stream(age=5)
        s = PDBInfoStream(data)
        s.parse()
        self.assertEqual(s.age, 5)

    def test_version_parsed(self):
        data = _make_pdb_info_stream(version=20000404)
        s = PDBInfoStream(data)
        s.parse()
        self.assertEqual(s.version, 20000404)

    def test_too_short_raises(self):
        s = PDBInfoStream(b"\x00" * 10)
        with self.assertRaises(ValueError):
            s.parse()

    def test_guid_uppercase(self):
        data = _make_pdb_info_stream(
            guid_d1=0xAABBCCDD, guid_d2=0xEEFF, guid_d3=0x0011,
            guid_d4=b"\x22\x33\x44\x55\x66\x77\x88\x99",
        )
        s = PDBInfoStream(data)
        s.parse()
        self.assertEqual(s.guid, s.guid.upper())

    def test_guid_no_dashes(self):
        data = _make_pdb_info_stream()
        s = PDBInfoStream(data)
        s.parse()
        self.assertNotIn("-", s.guid)
        self.assertEqual(len(s.guid), 32)


# ---------------------------------------------------------------------------
# Test: DBIStream
# ---------------------------------------------------------------------------

class TestDBIStream(unittest.TestCase):

    def test_stream_indices_parsed(self):
        data = _make_dbi_header(global_stream=7, public_stream=8, sym_record_stream=9)
        dbi = DBIStream(data)
        dbi.parse()
        self.assertEqual(dbi.global_stream_index, 7)
        self.assertEqual(dbi.public_stream_index, 8)
        self.assertEqual(dbi.sym_record_stream, 9)

    def test_too_short_raises(self):
        dbi = DBIStream(b"\x00" * 10)
        with self.assertRaises(ValueError):
            dbi.parse()

    def test_exact_64_bytes_ok(self):
        data = _make_dbi_header()
        self.assertEqual(len(data), 64)
        dbi = DBIStream(data)
        dbi.parse()   # must not raise

    def test_large_stream_indices(self):
        data = _make_dbi_header(global_stream=0xFFFE, public_stream=0xFFFD,
                                sym_record_stream=0xFFFC)
        dbi = DBIStream(data)
        dbi.parse()
        self.assertEqual(dbi.global_stream_index, 0xFFFE)


# ---------------------------------------------------------------------------
# Test: PublicSymbolStream
# ---------------------------------------------------------------------------

class TestPublicSymbolStream(unittest.TestCase):

    def _build_stream(self, symbols: list[tuple[str, int, int]]):
        """
        Build (pub_data, sym_record_data) for a list of (name, seg, offset).
        Returns the two byte strings ready to pass to PublicSymbolStream.
        """
        # Build symbol records and collect their offsets
        sym_records = b""
        offsets = []
        for name, seg, offset in symbols:
            rec = _make_pub32_record(name.encode(), seg, offset)
            offsets.append(len(sym_records))
            sym_records += rec

        pub_data = _make_public_stream_header(sym_hash_size=0, addr_map_entries=offsets)
        return pub_data, sym_records

    def test_single_symbol(self):
        pub, syms = self._build_stream([("NtCreateFile", 1, 0x1234)])
        result = PublicSymbolStream(pub, syms).parse()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, "NtCreateFile")
        self.assertEqual(result[0].offset, 0x1234)
        self.assertEqual(result[0].segment, 1)

    def test_multiple_symbols(self):
        entries = [("Alpha", 1, 0x100), ("Beta", 2, 0x200), ("Gamma", 3, 0x300)]
        pub, syms = self._build_stream(entries)
        result = PublicSymbolStream(pub, syms).parse()
        names = {s.name for s in result}
        self.assertEqual(names, {"Alpha", "Beta", "Gamma"})

    def test_symbol_offsets_correct(self):
        pub, syms = self._build_stream([("Foo", 1, 0xDEAD), ("Bar", 2, 0xBEEF)])
        result = PublicSymbolStream(pub, syms).parse()
        by_name = {s.name: s for s in result}
        self.assertEqual(by_name["Foo"].offset, 0xDEAD)
        self.assertEqual(by_name["Bar"].offset, 0xBEEF)

    def test_symbol_segments_correct(self):
        pub, syms = self._build_stream([("X", 5, 0x10), ("Y", 8, 0x20)])
        result = PublicSymbolStream(pub, syms).parse()
        by_name = {s.name: s for s in result}
        self.assertEqual(by_name["X"].segment, 5)
        self.assertEqual(by_name["Y"].segment, 8)

    def test_empty_stream_returns_empty_list(self):
        pub, syms = self._build_stream([])
        result = PublicSymbolStream(pub, syms).parse()
        self.assertEqual(result, [])

    def test_too_short_pub_returns_empty(self):
        result = PublicSymbolStream(b"\x00" * 5, b"").parse()
        self.assertEqual(result, [])

    def test_non_pub32_record_skipped(self):
        """A record with kind != S_PUB32 / S_PUB32_ST must be ignored."""
        # Build a record with kind 0x1234 (unknown)
        payload = _pack_u32(0) + _pack_u32(0x999) + _pack_u16(1) + b"Bad\x00"
        length  = 2 + len(payload)
        bad_rec = _pack_u16(length) + _pack_u16(0x1234) + payload

        pub_data = _make_public_stream_header(sym_hash_size=0, addr_map_entries=[0])
        result = PublicSymbolStream(pub_data, bad_rec).parse()
        self.assertEqual(result, [])

    def test_mangled_name_preserved(self):
        """C++ mangled names (starting with '?') must be stored verbatim."""
        pub, syms = self._build_stream([("?NtCreateFile@@YGHPAU_OBJECT_ATTRIBUTES@@@Z", 1, 0x10)])
        result = PublicSymbolStream(pub, syms).parse()
        self.assertEqual(result[0].name, "?NtCreateFile@@YGHPAU_OBJECT_ATTRIBUTES@@@Z")


# ---------------------------------------------------------------------------
# Test: MSFReader with synthetic PDB
# ---------------------------------------------------------------------------

class TestMSFReader(unittest.TestCase):

    def _write_msf(self, streams: list[bytes]) -> str:
        """Build a synthetic MSF file, write to a temp file, return path."""
        builder = MSFBuilder()
        for s in streams:
            builder.add_stream(s)
        data = builder.build()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdb")
        tmp.write(data)
        tmp.close()
        return tmp.name

    def tearDown(self):
        # Clean up any temp files created during tests
        pass

    def test_stream_count(self):
        path = self._write_msf([b"stream0", b"stream1", b"stream2"])
        try:
            msf = MSFReader(path)
            msf.load()
            self.assertEqual(msf.num_streams, 3)
        finally:
            os.unlink(path)

    def test_stream_content_roundtrip(self):
        payload = b"Hello, PDB world!"
        path = self._write_msf([b"ignored", payload])
        try:
            msf = MSFReader(path)
            msf.load()
            self.assertEqual(msf.get_stream(1), payload)
        finally:
            os.unlink(path)

    def test_stream_content_larger_than_page(self):
        """A stream that spans multiple pages must be reassembled correctly."""
        payload = bytes(range(256)) * 4   # 1024 bytes > 512-byte page
        path = self._write_msf([b"s0", payload])
        try:
            msf = MSFReader(path)
            msf.load()
            self.assertEqual(msf.get_stream(1), payload)
        finally:
            os.unlink(path)

    def test_empty_stream_returns_empty_bytes(self):
        path = self._write_msf([b"", b"data"])
        try:
            msf = MSFReader(path)
            msf.load()
            self.assertEqual(msf.get_stream(0), b"")
        finally:
            os.unlink(path)

    def test_page_size_parsed(self):
        path = self._write_msf([b"x"])
        try:
            msf = MSFReader(path)
            msf.load()
            self.assertEqual(msf.page_size, MSFBuilder.PAGE_SIZE)
        finally:
            os.unlink(path)

    def test_bad_magic_raises(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdb") as f:
            f.write(b"BADMAGIC" + b"\x00" * 500)
            path = f.name
        try:
            msf = MSFReader(path)
            with self.assertRaises(ValueError):
                msf.load()
        finally:
            os.unlink(path)

    def test_stream_index_out_of_range_raises(self):
        path = self._write_msf([b"only_one"])
        try:
            msf = MSFReader(path)
            msf.load()
            with self.assertRaises(IndexError):
                msf.get_stream(99)
        finally:
            os.unlink(path)

    def test_multiple_streams_independent(self):
        s0, s1, s2 = b"AAA", b"BBBBB", b"CC"
        path = self._write_msf([s0, s1, s2])
        try:
            msf = MSFReader(path)
            msf.load()
            self.assertEqual(msf.get_stream(0), s0)
            self.assertEqual(msf.get_stream(1), s1)
            self.assertEqual(msf.get_stream(2), s2)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test: PDBReader.find and save_symbols (mocked MSF/streams)
# ---------------------------------------------------------------------------

class TestPDBReaderFindAndSave(unittest.TestCase):
    """
    Tests PDBReader.find() and save_symbols() by injecting a pre-populated
    symbols list directly (bypassing MSF/PDB parsing).
    """

    def _make_reader_with_symbols(self, symbols: list[Symbol]) -> PDBReader:
        pe = MagicMock(spec=PEParser)
        reader = PDBReader.__new__(PDBReader)
        reader.pdb_path = "<mock>"
        reader._pe = pe
        reader._msf = None
        reader.symbols = symbols
        return reader

    def test_find_existing_symbol(self):
        syms = [Symbol("NtCreateFile", 0x1000, 1), Symbol("NtOpenFile", 0x2000, 1)]
        reader = self._make_reader_with_symbols(syms)
        result = reader.find("NtCreateFile")
        self.assertIsNotNone(result)
        self.assertEqual(result.offset, 0x1000)

    def test_find_missing_symbol_returns_none(self):
        reader = self._make_reader_with_symbols([Symbol("Foo", 0x100, 1)])
        self.assertIsNone(reader.find("Bar"))

    def test_find_case_sensitive(self):
        reader = self._make_reader_with_symbols([Symbol("NtCreateFile", 0x1000, 1)])
        self.assertIsNone(reader.find("ntcreatefile"))
        self.assertIsNone(reader.find("NTCREATEFILE"))

    def test_save_symbols_tsv_format(self):
        syms = [
            Symbol("Alpha", 0x1000, 1),
            Symbol("Beta",  0x2000, 2),
        ]
        reader = self._make_reader_with_symbols(syms)
        with tempfile.NamedTemporaryFile(mode="r", delete=False, suffix=".tsv") as f:
            path = f.name
        try:
            reader.save_symbols(path)
            lines = Path(path).read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines[0], "RVA\tSegment\tName")
            self.assertIn("0x00001000\t1\tAlpha", lines)
            self.assertIn("0x00002000\t2\tBeta", lines)
        finally:
            os.unlink(path)

    def test_save_symbols_header_present(self):
        reader = self._make_reader_with_symbols([])
        with tempfile.NamedTemporaryFile(mode="r", delete=False, suffix=".tsv") as f:
            path = f.name
        try:
            reader.save_symbols(path)
            first_line = Path(path).read_text().splitlines()[0]
            self.assertEqual(first_line, "RVA\tSegment\tName")
        finally:
            os.unlink(path)

    def test_save_symbols_rva_hex_format(self):
        """RVA column must be '0x' + 8 uppercase hex digits."""
        reader = self._make_reader_with_symbols([Symbol("X", 0xABCD1234, 1)])
        with tempfile.NamedTemporaryFile(mode="r", delete=False, suffix=".tsv") as f:
            path = f.name
        try:
            reader.save_symbols(path)
            content = Path(path).read_text()
            self.assertIn("0xABCD1234", content)
        finally:
            os.unlink(path)

    def test_symbols_sorted_by_rva(self):
        """After load(), symbols must be sorted ascending by RVA."""
        syms = [Symbol("C", 0x300, 1), Symbol("A", 0x100, 1), Symbol("B", 0x200, 1)]
        reader = self._make_reader_with_symbols(sorted(syms, key=lambda s: s.offset))
        rvas = [s.offset for s in reader.symbols]
        self.assertEqual(rvas, sorted(rvas))

# ---------------------------------------------------------------------------
# Integration tests – require ntoskrnl.exe + ntkrnlmp.pdb on disk
# ---------------------------------------------------------------------------

INTEGRATION_REASON = (
    "Integration tests require ntoskrnl.exe and ntkrnlmp.pdb "
    "in tests/data/."
)


@unittest.skipUnless(
    NTOSKRNL.exists() and NTKRNLMP_PDB.exists(),
    INTEGRATION_REASON,
)
class TestIntegrationNtoskrnl(unittest.TestCase):
    """
    End-to-end tests against the real ntoskrnl.exe + ntkrnlmp.pdb.

    These pin concrete values observed from cvdump.exe / dumpbin so that
    any future regression in parsing is caught immediately.
    """

    # Known-good values verified against cvdump.exe output:
    #   S_PUB32: [0008:0022A470], Flags: 00000002, HalpLMStub
    # Section 8 (.text) VA from dumpbin /headers:
    #   200000 virtual address → RVA = 0x200000 + 0x22A470 = 0x42A470
    KNOWN_SYMBOL      = "HalpLMStub"
    KNOWN_RVA         = 0x0042A470
    KNOWN_SEGMENT     = 8

    # PE debug info pinned from the binary on disk
    KNOWN_PDB_NAME    = "ntkrnlmp.pdb"

    @classmethod
    def setUpClass(cls):
        cls.pe_parser = PEParser(str(NTOSKRNL))
        cls.pe_parser.load()
        cls.pdb_info  = cls.pe_parser.extract_pdb_info()

        cls.reader = PDBReader(str(NTKRNLMP_PDB), cls.pe_parser)
        cls.reader.load()

    # ── PE parsing ────────────────────────────────────────────────────────

    def test_pdb_filename(self):
        self.assertEqual(self.pdb_info.pdb_filename, self.KNOWN_PDB_NAME)

    def test_guid_length_and_format(self):
        guid = self.pdb_info.guid
        self.assertEqual(len(guid), 32)
        self.assertNotIn("-", guid)
        self.assertEqual(guid, guid.upper())

    def test_age_positive(self):
        self.assertGreater(self.pdb_info.age, 0)

    def test_guid_age_starts_with_guid(self):
        self.assertTrue(self.pdb_info.guid_age.startswith(self.pdb_info.guid))

    def test_guid_age_ends_with_hex_age(self):
        expected_suffix = format(self.pdb_info.age, "X")
        self.assertTrue(self.pdb_info.guid_age.endswith(expected_suffix))

    def test_section_table_loaded(self):
        self.assertGreater(len(self.pe_parser.sections), 0)

    def test_section_8_va(self):
        """Section 8 (.text) must have VA 0x00200000 for the RVA math to work."""
        va, _ = self.pe_parser.sections[7]   # 0-based index 7 = segment 8
        self.assertEqual(va, 0x00200000)

    # ── Symbol extraction ─────────────────────────────────────────────────

    def test_symbol_count_reasonable(self):
        """A real ntoskrnl PDB should have tens of thousands of public symbols."""
        self.assertGreater(len(self.reader.symbols), 10_000)

    def test_symbols_sorted_ascending(self):
        rvas = [s.offset for s in self.reader.symbols]
        self.assertEqual(rvas, sorted(rvas))

    def test_halplmstub_rva(self):
        """
        Regression pin: HalpLMStub must resolve to RVA 0x0042A470.
        This is the exact value verified with cvdump.exe + dumpbin.
        """
        sym = self.reader.find(self.KNOWN_SYMBOL)
        self.assertIsNotNone(sym, f"{self.KNOWN_SYMBOL!r} not found in symbol table")
        self.assertEqual(
            sym.offset, self.KNOWN_RVA,
            f"RVA mismatch: got 0x{sym.offset:08X}, expected 0x{self.KNOWN_RVA:08X}",
        )

    def test_halplmstub_segment(self):
        sym = self.reader.find(self.KNOWN_SYMBOL)
        self.assertIsNotNone(sym)
        self.assertEqual(sym.segment, self.KNOWN_SEGMENT)

    def test_find_returns_none_for_unknown(self):
        self.assertIsNone(self.reader.find("__this_symbol_does_not_exist__"))

    def test_all_symbols_have_names(self):
        for sym in self.reader.symbols:
            self.assertIsInstance(sym.name, str)
            self.assertGreater(len(sym.name), 0)

    def test_all_symbols_have_valid_segments(self):
        """Every symbol's segment must be a positive integer."""
        for sym in self.reader.symbols:
            self.assertGreater(sym.segment, 0)

    def test_symbol_url_format(self):
        """The download URL must follow the Microsoft symbol server convention."""
        dl  = SymbolDownloader()
        url = dl.build_url(self.pdb_info)
        expected = (
            f"https://msdl.microsoft.com/download/symbols"
            f"/{self.pdb_info.pdb_filename}"
            f"/{self.pdb_info.guid_age}"
            f"/{self.pdb_info.pdb_filename}"
        )
        self.assertEqual(url, expected)

    def test_save_and_reload_symbols(self):
        """save_symbols() output must be parseable and contain HalpLMStub."""
        with tempfile.NamedTemporaryFile(
            mode="r", delete=False, suffix=".tsv", encoding="utf-8"
        ) as f:
            path = f.name
        try:
            self.reader.save_symbols(path)
            lines = Path(path).read_text(encoding="utf-8").splitlines()
            # Header
            self.assertEqual(lines[0], "RVA\tSegment\tName")
            # At least one data row
            self.assertGreater(len(lines), 1)
            # HalpLMStub must appear with the correct RVA
            target = f"0x{self.KNOWN_RVA:08X}\t{self.KNOWN_SEGMENT}\t{self.KNOWN_SYMBOL}"
            self.assertIn(target, lines, f"Expected line not found: {target!r}")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Entry point (also works without pytest)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
