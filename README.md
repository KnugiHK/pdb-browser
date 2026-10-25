# PDB Browser

A fast, lightweight CLI shell and GUI browser for inspecting Windows Portable Executable (PE) files and their matching Microsoft Program Database (PDB) symbols.

PDB Browser automatically extracts CodeView RSDS debug signatures (GUID & Age) from PE binaries, fetches matching symbol files directly from the Microsoft Symbol Server, parses public symbol tables and RVAs, and provides both an interactive terminal interface and a dark-themed desktop GUI.

---

## Features

- **Automatic Symbol Resolution:** Parses PE debug directories, constructs Microsoft Symbol Server queries, and caches downloaded PDBs locally.
- **Zero-Native Dependencies for PDB Parsing:** Includes an in-process, pure-Python MSF 7.0/DBI stream parser for extracting public symbols (`S_PUB32`) and calculating accurate Relative Virtual Addresses (RVAs).
- **Interactive Terminal Shell (`--cli`):** 
  - Inline ghost-text predictive autocompletion (Tab / Right Arrow).
  - Persistent command history (Up / Down Arrow).
  - ANSI terminal support across Windows and POSIX.
- **Graphical Browser (`--gui`):** 
  - Fast filter-as-you-type search across tens of thousands of symbols.
  - Sortable table views (RVA, Segment, Symbol Name).
  - Instant clipboard copy for RVAs on double-click or detail panel selection.

---

## Requirements

- **Python:** 3.14+ (officially supported)
- **OS:** Windows, Linux, or macOS
- **GUI Dependency:** `tkinter` (bundled with official Python installers on Windows/macOS; on Debian/Ubuntu install via `sudo apt install python3-tk`)

---

## Installation

### From Source

```bash
git clone https://github.com/KnugiHK/pdb-browser
cd pdb-browser
pip install .

```

For development (includes test utilities):

```bash
pip install -e ".[dev]"

```

---

## Usage

You can launch PDB Browser using either the installed entry point or directly via `main.py`:

```bash
# Launch interactive terminal shell
pdb-browser --cli <path_to_binary.exe|dll>

# Launch graphical browser
pdb-browser --gui <path_to_binary.exe|dll>

```

> **Note:** If no input file is specified, the CLI prompts for a path in the console, while the GUI opens a native file picker dialog. If neither `--cli` nor `--gui` is specified, the application automatically detects whether an active console is attached.
> 
> 

### Common Options

| Option | Flag | Description | Default |
| --- | --- | --- | --- |
| **Output Directory** | `-o`, `--output-dir` | Path to store downloaded PDB symbol files. | System temporary folder / Current working directory |
| **No Download** | `--no-download` | Use an existing cached PDB; fail if not found locally. | `False` |
| **CLI Mode** | `--cli` | Force interactive terminal shell frontend. | Auto-detected |
| **GUI Mode** | `--gui` | Force graphical symbol browser frontend. | Auto-detected |

---

## Standalone Script Usage (`pdb_tool.py`)

For headless scripting or pipeline workflows, `pdb_tool.py` can be used standalone:

```bash
# Print first 50 symbols to stdout
python pdb_tool.py ntoskrnl.exe

# Find a specific function RVA
python pdb_tool.py ntoskrnl.exe --find NtCreateFile

# Dump all public symbols to a TSV file
python pdb_tool.py ntoskrnl.exe --save-symbols symbols.tsv

```

---

## Testing

Run unit tests via `pytest`:

```bash
pytest

```

---

## License

This project is licensed under the terms of the GNU General Public License v3.0 (GPL-3.0).
