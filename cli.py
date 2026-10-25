#!/usr/bin/env python3
"""
cli.py - Interactive symbol search shell for PE/PDB files.

Usage:
    python cli.py                        # prompts for a PE path
    python cli.py ntoskrnl.exe
    python cli.py ntoskrnl.exe --no-download
"""

import argparse
import os
import sys
import platform
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from pdb_tool import PEParser, PDBReader, Symbol, default_pdb_dir
from symbols import SymbolMatcher, load_symbols

_IS_WINDOWS = platform.system() == "Windows"

GREY   = "\x1b[90m"
RESET  = "\x1b[0m"
BOLD   = "\x1b[1m"
GREEN  = "\x1b[32m"
CYAN   = "\x1b[36m"
RED    = "\x1b[31m"
_VT_ENABLED = not _IS_WINDOWS

KEY_ENTER     = "ENTER"
KEY_BACKSPACE = "BACKSPACE"
KEY_TAB       = "TAB"
KEY_ESCAPE    = "ESCAPE"
KEY_CTRL_C    = "CTRL_C"
KEY_CTRL_U    = "CTRL_U"
KEY_CTRL_W    = "CTRL_W"
KEY_LEFT      = "LEFT"
KEY_RIGHT     = "RIGHT"
KEY_HOME      = "HOME"
KEY_END       = "END"
KEY_DELETE    = "DELETE"
KEY_UP        = "UP"
KEY_DOWN      = "DOWN"
KEY_CHAR      = "CHAR"  # printable character; value carried in the second return element


def _enable_vt_processing() -> None:
    """Enable ANSI escape sequences on Windows and fall back if unsupported."""
    global _VT_ENABLED, GREY, RESET, BOLD, GREEN, CYAN, RED
    if not _IS_WINDOWS:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_std_handle = kernel32.GetStdHandle
    get_std_handle.argtypes = [wintypes.DWORD]
    get_std_handle.restype = wintypes.HANDLE
    handle = get_std_handle(wintypes.DWORD(-11 & 0xFFFFFFFF))  # STD_OUTPUT_HANDLE
    mode = wintypes.DWORD()

    get_console_mode = kernel32.GetConsoleMode
    get_console_mode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    get_console_mode.restype = wintypes.BOOL
    set_console_mode = kernel32.SetConsoleMode
    set_console_mode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    set_console_mode.restype = wintypes.BOOL

    if (not handle or not get_console_mode(handle, ctypes.byref(mode))
            or not set_console_mode(handle, mode.value | 0x0004)):
        _VT_ENABLED = False
        GREY = RESET = BOLD = GREEN = CYAN = RED = ""
        return
    _VT_ENABLED = True


def _write(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


if _IS_WINDOWS:
    import msvcrt

    def read_key() -> tuple[str, str]:
        """Read one keypress. Returns (KEY_CONSTANT, char)."""
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            ch2 = msvcrt.getwch()
            _MAP = {
                "K": KEY_LEFT,  "M": KEY_RIGHT, "G": KEY_HOME,
                "O": KEY_END,   "S": KEY_DELETE, "H": KEY_UP, "P": KEY_DOWN,
                "\x4b": KEY_LEFT,  "\x4d": KEY_RIGHT, "\x47": KEY_HOME,
                "\x4f": KEY_END,   "\x53": KEY_DELETE, "\x48": KEY_UP, "\x50": KEY_DOWN,
            }
            return _MAP.get(ch2, KEY_CHAR), ""
        if ch == "\r":   return KEY_ENTER, ""
        if ch in ("\x08", "\x7f"): return KEY_BACKSPACE, ""
        if ch == "\t":   return KEY_TAB, ""
        if ch == "\x1b": return KEY_ESCAPE, ""
        if ch == "\x03": return KEY_CTRL_C, ""
        if ch == "\x15": return KEY_CTRL_U, ""
        if ch == "\x17": return KEY_CTRL_W, ""
        if ch.isprintable(): return KEY_CHAR, ch
        return KEY_CHAR, ""

else:
    import tty
    import termios
    import select as _select

    def _peek(fd: int, timeout: float = 0.1) -> str:
        """Read one byte from fd if available within timeout, else return ''."""
        if _select.select([fd], [], [], timeout)[0]:
            return os.read(fd, 1).decode("latin-1")
        return ""

    def read_key() -> tuple[str, str]:
        """
        Read one keypress using raw terminal mode. Returns (KEY_CONSTANT, char).

        All reading — including escape-sequence continuation — happens inside
        a single raw-mode block so no bytes are lost between mode switches.
        """
        fd  = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = os.read(fd, 1).decode("latin-1")

            if ch in ("\r", "\n"): return KEY_ENTER, ""
            if ch in ("\x08", "\x7f"): return KEY_BACKSPACE, ""
            if ch == "\t":   return KEY_TAB, ""
            if ch == "\x03": return KEY_CTRL_C, ""
            if ch == "\x15": return KEY_CTRL_U, ""
            if ch == "\x17": return KEY_CTRL_W, ""

            if ch == "\x1b":
                # 100 ms — enough for any terminal to flush the full escape sequence
                seq = _peek(fd, 0.1)
                if not seq:
                    return KEY_ESCAPE, ""

                if seq == "[":
                    seq2 = _peek(fd, 0.1)
                    if seq2 == "A": return KEY_UP, ""
                    if seq2 == "B": return KEY_DOWN, ""
                    if seq2 == "C": return KEY_RIGHT, ""
                    if seq2 == "D": return KEY_LEFT, ""
                    if seq2 == "H": return KEY_HOME, ""
                    if seq2 == "F": return KEY_END, ""
                    if seq2 in ("1", "7"):
                        _peek(fd, 0.1)  # consume trailing '~'
                        return KEY_HOME, ""
                    if seq2 in ("4", "8"):
                        _peek(fd, 0.1)
                        return KEY_END, ""
                    if seq2 == "3":
                        _peek(fd, 0.1)  # consume '~'
                        return KEY_DELETE, ""
                    while _peek(fd, 0.05):  # drain unknown CSI sequence
                        pass
                    return KEY_CHAR, ""

                if seq == "O":
                    seq2 = _peek(fd, 0.1)
                    if seq2 == "H": return KEY_HOME, ""
                    if seq2 == "F": return KEY_END, ""
                    if seq2 == "A": return KEY_UP, ""
                    if seq2 == "B": return KEY_DOWN, ""
                    if seq2 == "C": return KEY_RIGHT, ""
                    if seq2 == "D": return KEY_LEFT, ""
                    return KEY_CHAR, ""

                return KEY_CHAR, ""

            if ch.isprintable():
                return KEY_CHAR, ch
            return KEY_CHAR, ""

        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


class PredictiveInput:
    """
    Single-line input prompt with inline ghost-text completion and history.

    Keybindings:
      Printable chars  insert at cursor
      Backspace        delete left
      Ctrl-W           delete word left
      Ctrl-U           delete to start of line
      Left/Right       move cursor
      Home/End         jump to start/end
      Delete           delete under cursor
      Tab / Right(eol) accept ghost prediction
      Up/Down          walk history
      Enter            submit
      Escape / Ctrl-C  cancel (returns empty string)
    """

    PROMPT = f"{CYAN}symbol>{RESET} "

    def __init__(self, matcher: SymbolMatcher):
        self._matcher   = matcher
        self._buf: list[str] = []
        self._cur: int  = 0
        self._prediction: str = ""
        self._history: list[str] = []
        # _hist_idx == len(_history) means the user is on the live (unsaved) input
        self._hist_idx: int = 0
        self._saved_buf: list[str] = []

    def readline(self) -> Optional[str]:
        """Run the input loop. Returns the submitted string (empty string = cancel)."""
        if not _VT_ENABLED:
            return input("symbol> ")

        self._buf       = []
        self._cur       = 0
        self._prediction = ""
        self._hist_idx  = len(self._history)
        self._saved_buf = []
        self._redraw()

        while True:
            key, char = read_key()
            result = self._handle_key(key, char)
            if result is not None:
                _write("\n")
                text = result.strip()
                if text and (not self._history or self._history[-1] != text):
                    self._history.append(text)
                return result
            self._update_prediction()
            self._redraw()

    def _handle_key(self, key: str, char: str) -> Optional[str]:
        if key == KEY_CTRL_C:
            _write("\n")
            return ""
        if key == KEY_ESCAPE:
            _write("\n")
            return ""
        if key == KEY_ENTER:
            return "".join(self._buf)
        if key == KEY_TAB:
            self._accept_prediction()
            return None
        if key == KEY_BACKSPACE:
            if self._cur > 0:
                self._buf.pop(self._cur - 1)
                self._cur -= 1
            return None
        if key == KEY_CTRL_U:
            self._buf = self._buf[self._cur:]
            self._cur = 0
            return None
        if key == KEY_CTRL_W:
            while self._cur > 0 and self._buf[self._cur - 1] == " ":
                self._buf.pop(self._cur - 1)
                self._cur -= 1
            while self._cur > 0 and self._buf[self._cur - 1] != " ":
                self._buf.pop(self._cur - 1)
                self._cur -= 1
            return None
        if key == KEY_LEFT:
            if self._cur > 0:
                self._cur -= 1
            return None
        if key == KEY_RIGHT:
            if self._cur < len(self._buf):
                self._cur += 1
            else:
                self._accept_prediction()
            return None
        if key == KEY_HOME:
            self._cur = 0
            return None
        if key == KEY_END:
            self._cur = len(self._buf)
            return None
        if key == KEY_DELETE:
            if self._cur < len(self._buf):
                self._buf.pop(self._cur)
            return None
        if key == KEY_UP:
            self._history_prev()
            return None
        if key == KEY_DOWN:
            self._history_next()
            return None
        if key == KEY_CHAR and char.isprintable():
            self._buf.insert(self._cur, char)
            self._cur += 1
        return None

    def _history_prev(self) -> None:
        if not self._history:
            return
        if self._hist_idx == len(self._history):
            self._saved_buf = self._buf[:]
        if self._hist_idx > 0:
            self._hist_idx -= 1
            self._buf = list(self._history[self._hist_idx])
            self._cur = len(self._buf)

    def _history_next(self) -> None:
        if self._hist_idx < len(self._history):
            self._hist_idx += 1
            if self._hist_idx == len(self._history):
                self._buf = self._saved_buf[:]
            else:
                self._buf = list(self._history[self._hist_idx])
            self._cur = len(self._buf)

    def _update_prediction(self) -> None:
        text = "".join(self._buf)
        if text:
            pred = self._matcher.predict(text)
            self._prediction = pred if pred and pred != text else ""
        else:
            self._prediction = ""

    def _accept_prediction(self) -> None:
        if self._prediction:
            self._buf = list(self._prediction)
            self._cur = len(self._buf)
            self._prediction = ""

    def _redraw(self) -> None:
        typed = "".join(self._buf)
        ghost = self._prediction[len(typed):] if self._prediction else ""
        _write("\r\x1b[2K" + self.PROMPT + typed + GREY + ghost + RESET)
        prompt_len = len("symbol> ")
        move_back  = prompt_len + len(typed) + len(ghost) - (prompt_len + self._cur)
        if move_back > 0:
            _write(f"\x1b[{move_back}D")


def _show_result(sym: Symbol) -> None:
    _write(
        f"  {GREEN}RVA{RESET}     0x{sym.offset:08X}\n"
        f"  {GREEN}Segment{RESET} {sym.segment}\n"
        f"  {GREEN}Name{RESET}    {sym.name}\n"
    )


def _show_not_found(name: str) -> None:
    _write(f"  {RED}Not found:{RESET} {name!r}\n")


def _show_banner(num_symbols: int, pdb_name: str) -> None:
    _write(
        f"\n{BOLD}PDB Symbol Shell{RESET}  —  {CYAN}{pdb_name}{RESET}"
        f"  ({num_symbols:,} symbols)\n"
        f"{GREY}Type a symbol name. Tab/→ to complete. ↑↓ for history. "
        f"Enter to look up. Empty Enter or Ctrl-C to quit.{RESET}\n\n"
    )


def run_shell(reader: PDBReader) -> None:
    matcher = SymbolMatcher(reader.symbols)
    inp     = PredictiveInput(matcher)
    _show_banner(len(reader.symbols), Path(reader.pdb_path).name)

    while True:
        try:
            text = inp.readline()
        except KeyboardInterrupt:
            _write("\n")
            break

        if not text:
            break
        text = text.strip()
        if not text:
            break

        sym = matcher.exact(text) or matcher.exact_ci(text)
        if sym:
            _show_result(sym)
        else:
            _show_not_found(text)
        _write("\n")

    _write(f"{GREY}Bye.{RESET}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactive symbol search shell for PE/PDB files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python cli.py\n"
            "  python cli.py ntoskrnl.exe\n"
            "  python cli.py ntoskrnl.exe --no-download\n"
            "  python cli.py ntoskrnl.exe -o /tmp/symbols\n"
            "  python cli.py ntoskrnl.exe --save-to-cwd\n"
        ),
    )
    parser.add_argument("pe_file", nargs="?", default=None,
                        help="Path to the EXE or DLL. Prompted if omitted.")
    parser.add_argument(
        "--output-dir", "-o", default=None,
        help=(
            "Directory for the downloaded PDB. "
            f"Defaults to the system temp folder ({default_pdb_dir()})."
        ),
    )
    parser.add_argument(
        "--save-to-cwd", action="store_true",
        help="Save the downloaded PDB to the current working directory instead of temp.",
    )
    parser.add_argument("--no-download", action="store_true",
                        help="Skip downloading; use an already-cached PDB.")
    return parser.parse_args()


def main() -> None:
    _enable_vt_processing()
    if _IS_WINDOWS and not _VT_ENABLED:
        print("[!] ANSI terminal support unavailable; using basic line input.", file=sys.stderr)
    args = parse_args()

    pe_path = args.pe_file
    if not pe_path:
        pe_path = input("PE file path: ").strip().strip('"')

    if not os.path.isfile(pe_path):
        print(f"[!] File not found: {pe_path}", file=sys.stderr)
        sys.exit(1)

    # Resolve output directory: explicit > --save-to-cwd > temp
    if args.output_dir:
        output_dir = args.output_dir
    elif args.save_to_cwd:
        output_dir = os.getcwd()
    else:
        output_dir = default_pdb_dir()

    _, reader = load_symbols(
        pe_path=pe_path,
        output_dir=output_dir,
        no_download=args.no_download,
    )
    run_shell(reader)


if __name__ == "__main__":
    main()
