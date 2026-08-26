#!/usr/bin/env python3
"""
hextract.py - format-driven decoder for hex word dumps (Vivado ILA etc.).

Packet layouts are described declaratively in TOML files (see formats/).
Runs a live tkinter GUI by default, or decodes headless from the CLI:

    hextract.py                            # GUI
    hextract.py -f blm_interlock_512 cap.txt
    hextract.py --list-formats

Requires Python >= 3.11 (tomllib). CLI mode works without tkinter.
"""

import argparse
import ast
import glob
import os
import re
import struct
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

try:
    import tomllib
except ImportError:
    tomllib = None

try:
    import tkinter as tk
    from tkinter import ttk, filedialog
    HAVE_TK = True
except ImportError:
    HAVE_TK = False

FORMATS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "formats")

TYPE_FMT = {
    "u8": "B", "u16": "H", "u32": "I", "u64": "Q",
    "i8": "b", "i16": "h", "i32": "i", "i64": "q",
    "f32": "f", "f64": "d",
}
TYPE_BITS = {t: struct.calcsize(c) * 8 for t, c in TYPE_FMT.items()}

CALL_WHITELIST = {"any", "all", "min", "max", "abs", "len"}

NONHEX = re.compile(r"[^0-9a-fA-F]+")
PREFIX = re.compile(r"0[xX]")


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class Field:
    name: str
    type: str
    count: int = 1
    bits: Optional[Tuple[int, int]] = None  # (hi, lo), hi == lo for single bit
    radix: Optional[str] = None
    scale: Optional[float] = None


@dataclass(frozen=True)
class Rule:
    when_src: str
    code: object
    name: str = ""
    bg: Optional[str] = None
    fg: Optional[str] = None


class PacketFormat:
    def __init__(self, name, description, word_bits, byte_order, fields, rules):
        self.name = name
        self.description = description
        self.word_bits = word_bits
        self.byte_order = byte_order
        self.fields = fields
        self.rules = rules
        self._struct = None
        self.rule_warnings = []
        seen_rules = {}
        for i, rule in enumerate(rules):
            if rule.when_src in seen_rules:
                self.rule_warnings.append(
                    "rule %d is identical to rule %d; first match wins" %
                    (i + 1, seen_rules[rule.when_src] + 1))
            else:
                seen_rules[rule.when_src] = i

    @property
    def word_bytes(self):
        return self.word_bits // 8

    def columns(self):
        cols = []
        for f in self.fields:
            if f.count == 1:
                cols.append(f.name)
            else:
                cols.extend("%s%d" % (f.name, i) for i in range(f.count))
        return cols

    def struct(self):
        if self._struct is None:
            s = "<" + "".join(TYPE_FMT[f.type] * f.count for f in self.fields)
            used = sum(TYPE_BITS[f.type] * f.count for f in self.fields) // 8
            s += "x" * (self.word_bytes - used)
            self._struct = struct.Struct(s)
        return self._struct


# ---------------------------------------------------------------- formats

ALLOWED_NODES = {
    ast.Expression, ast.BoolOp, ast.UnaryOp, ast.BinOp, ast.Compare, ast.Call,
    ast.Name, ast.Constant, ast.Tuple, ast.List, ast.GeneratorExp,
    ast.comprehension, ast.Subscript, ast.Slice, ast.Load, ast.Store,
    ast.And, ast.Or, ast.Not, ast.UAdd, ast.USub,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
}


def compile_rule(src, field_names):
    try:
        tree = ast.parse(src, mode="eval")
    except SyntaxError as e:
        raise FormatError("rule syntax error: %s" % e)
    comp_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.comprehension):
            for sub in ast.walk(node.target):
                if isinstance(sub, ast.Name):
                    comp_names.add(sub.id)
    for node in ast.walk(tree):
        if type(node) not in ALLOWED_NODES:
            raise FormatError("rule uses disallowed construct '%s'" % type(node).__name__)
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in CALL_WHITELIST:
                raise FormatError("rule calls disallowed function")
        if isinstance(node, ast.Name):
            if node.id.startswith("_"):
                raise FormatError("rule references private name '%s'" % node.id)
            allowed = field_names | comp_names | CALL_WHITELIST
            if node.id not in allowed:
                raise FormatError("rule references unknown name '%s'" % node.id)
    return compile(tree, "<rule>", "eval")


def _parse_bits(value, type_bits):
    if isinstance(value, bool):
        raise FormatError("bits must be an int or 'hi:lo' string")
    if isinstance(value, int):
        hi = lo = value
    elif isinstance(value, str) and ":" in value:
        hi_s, lo_s = value.split(":", 1)
        try:
            hi, lo = int(hi_s), int(lo_s)
        except ValueError:
            raise FormatError("bits '%s' is not 'hi:lo'" % value)
    else:
        raise FormatError("bits must be an int or 'hi:lo' string")
    if hi < lo or lo < 0 or hi >= type_bits:
        raise FormatError("bits '%s' out of range for %d-bit type" % (value, type_bits))
    return hi, lo


def load_format(path):
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise FormatError(str(e))

    meta = data.get("format")
    if not isinstance(meta, dict):
        raise FormatError("missing [format] table")
    name = meta.get("name")
    if not isinstance(name, str) or not name:
        raise FormatError("format.name missing")
    word_bits = meta.get("word_bits")
    if not isinstance(word_bits, int) or word_bits <= 0 or word_bits % 8:
        raise FormatError("format.word_bits must be a positive multiple of 8")
    byte_order = meta.get("byte_order", "msb-first")
    if byte_order not in ("msb-first", "lsb-first"):
        raise FormatError("format.byte_order must be 'msb-first' or 'lsb-first'")
    description = meta.get("description", "")

    raw_fields = data.get("field")
    if not isinstance(raw_fields, list) or not raw_fields:
        raise FormatError("at least one [[field]] is required")
    fields, seen = [], set()
    used_bits = 0
    for i, fd in enumerate(raw_fields):
        fname = fd.get("name")
        if not isinstance(fname, str) or not fname:
            raise FormatError("field %d: name missing" % i)
        if fname in seen:
            raise FormatError("field '%s' defined twice" % fname)
        seen.add(fname)
        ftype = fd.get("type")
        if ftype not in TYPE_FMT:
            raise FormatError("field '%s': unknown type '%s'" % (fname, ftype))
        count = fd.get("count", 1)
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise FormatError("field '%s': count must be an integer >= 1" % fname)
        bits = _parse_bits(fd["bits"], TYPE_BITS[ftype]) if "bits" in fd else None
        radix = fd.get("radix")
        if radix is not None and radix not in ("hex", "dec"):
            raise FormatError("field '%s': radix must be 'hex' or 'dec'" % fname)
        scale = fd.get("scale")
        if scale is not None and (isinstance(scale, bool) or not isinstance(scale, (int, float))):
            raise FormatError("field '%s': scale must be a number" % fname)
        fields.append(Field(fname, ftype, count, bits, radix, scale))
        used_bits += TYPE_BITS[ftype] * count
    if used_bits > word_bits:
        raise FormatError("fields use %d bits but word is %d bits" % (used_bits, word_bits))

    rules = []
    for i, rd in enumerate(data.get("rule", [])):
        when = rd.get("when")
        if not isinstance(when, str) or not when:
            raise FormatError("rule %d: when missing" % i)
        bg, fg = rd.get("bg"), rd.get("fg")
        rname = rd.get("name", "Rule %d" % (i + 1))
        if not isinstance(rname, str) or not rname:
            raise FormatError("rule %d: name must be a non-empty string" % i)
        if bg is None and fg is None:
            raise FormatError("rule %d: needs bg and/or fg color" % i)
        for cname, cval in (("bg", bg), ("fg", fg)):
            if cval is not None and (not isinstance(cval, str) or not cval):
                raise FormatError("rule %d: %s must be a color string" % (i, cname))
        rules.append(Rule(when, compile_rule(when, seen), rname, bg, fg))

    return PacketFormat(name, description, word_bits, byte_order, fields, rules)


def discover_formats(directory=FORMATS_DIR):
    return sorted(glob.glob(os.path.join(directory, "*.toml")))


def resolve_format(spec):
    candidates = [spec, spec + ".toml",
                  os.path.join(FORMATS_DIR, spec),
                  os.path.join(FORMATS_DIR, spec + ".toml")]
    for c in candidates:
        if os.path.isfile(c):
            return load_format(c)
    raise FormatError("unknown format '%s' (try --list-formats)" % spec)


# ---------------------------------------------------------------- decoding

def sanitize_hex(text):
    return NONHEX.sub("", PREFIX.sub("", text))


def extract_bits(value, bits):
    hi, lo = bits
    return (value >> lo) & ((1 << (hi - lo + 1)) - 1)


def hex_to_words(text, fmt, reverse=None):
    """Decode hex text into per-word field dicts.

    Returns (rows, remainder_bytes, error). reverse=None means follow
    fmt.byte_order.
    """
    if reverse is None:
        reverse = fmt.byte_order == "msb-first"
    hx = sanitize_hex(text)
    if not hx:
        return [], 0, None
    if len(hx) % 2:
        return [], 0, "odd number of hex characters"
    data = bytes.fromhex(hx)
    wb = fmt.word_bytes
    n = len(data) // wb
    if n == 0:
        return [], len(data), "need %d B per word (%d-bit), got %d B" % (
            wb, fmt.word_bits, len(data))
    unpack = fmt.struct().unpack
    rows = []
    for i in range(n):
        chunk = data[i * wb:(i + 1) * wb]
        if reverse:
            chunk = chunk[::-1]
        vals = unpack(chunk)
        row, pos = {}, 0
        for f in fmt.fields:
            take = vals[pos:pos + f.count]
            pos += f.count
            if f.bits is not None:
                take = tuple(extract_bits(v, f.bits) for v in take)
            row[f.name] = take[0] if f.count == 1 else take
        rows.append(row)
    return rows, len(data) % wb, None


def eval_rule(rule, env):
    matched, _ = eval_rule_result(rule, env)
    return matched


def eval_rule_result(rule, env):
    try:
        return bool(eval(rule.code, {"__builtins__": {}}, env)), None
    except Exception as e:
        return False, str(e)


def rule_env(fmt, row):
    env = {"any": any, "all": all, "min": min, "max": max, "abs": abs, "len": len}
    env.update(row)
    return env


def row_tags(fmt, row, idx):
    matched, _ = evaluate_row(fmt, row)
    # Treeview tag precedence varies by Tk version; never mix stripe and rule.
    tags = ["stripe"] if idx % 2 == 1 and matched is None else []
    if matched is not None:
        tags.append("rule%d" % matched)
    return tags


def evaluate_row(fmt, row):
    env = rule_env(fmt, row)
    errors = []
    for i, rule in enumerate(fmt.rules):
        matched, error = eval_rule_result(rule, env)
        if error:
            errors.append((i, error))
        if matched:
            return i, errors
    return None, errors


def rule_display_name(rule, index):
    return rule.name or "Rule %d" % (index + 1)


def format_cell(field, value):
    if field.scale is not None:
        value = value * field.scale
    if field.radix == "hex" and isinstance(value, int) and not isinstance(value, bool):
        return "-0x%x" % (-value) if value < 0 else "0x%x" % value
    if isinstance(value, float):
        return "%g" % value
    return str(value)


# ---------------------------------------------------------------- CLI

def cli_decode(fmt, text, no_header):
    rows, rem, err = hex_to_words(text, fmt)
    if err:
        print("hextract: %s" % err, file=sys.stderr)
        return 1
    header = ["#"] + fmt.columns()
    body = []
    for i, row in enumerate(rows):
        cells = [str(i)]
        for f in fmt.fields:
            v = row[f.name]
            if f.count == 1:
                cells.append(format_cell(f, v))
            else:
                cells.extend(format_cell(f, x) for x in v)
        body.append(cells)
    widths = []
    for c, h in enumerate(header):
        w = len(h)
        for r in body:
            w = max(w, len(r[c]))
        widths.append(w)
    if body and not no_header:
        print("  ".join(h.rjust(w) for h, w in zip(header, widths)))
    for r in body:
        print("  ".join(cell.rjust(w) for cell, w in zip(r, widths)))
    if rem:
        print("hextract: %d trailing bytes ignored" % rem, file=sys.stderr)
    return 0


def cli_list_formats():
    paths = discover_formats()
    if not paths:
        print("no format files in %s" % FORMATS_DIR)
        return 0
    for p in paths:
        try:
            fmt = load_format(p)
            print("%-24s %4d-bit  %s" % (fmt.name, fmt.word_bits, fmt.description))
        except FormatError as e:
            print("%-24s BROKEN: %s" % (os.path.basename(p), e))
    return 0


# ---------------------------------------------------------------- GUI

class App:
    TAG_STRIPE = "#f2f4f8"
    MAX_GUI_ROWS = 10000

    def __init__(self, root):
        self.root = root
        root.title("hextract")

        self.formats = {}
        self.byte_order_var = tk.StringVar(value="MSB-first")
        self.search_var = tk.StringVar()
        self.anomalies_only_var = tk.BooleanVar(value=False)
        self._debounce = None
        self._anomaly_items = []

        top = ttk.Frame(root, padding=(8, 6))
        top.pack(fill="x")
        ttk.Label(top, text="Format:").pack(side="left")
        self.combo = ttk.Combobox(top, state="readonly", width=28)
        self.combo.pack(side="left", padx=6)
        self.combo.bind("<<ComboboxSelected>>", self.on_format_change)
        ttk.Button(top, text="Open format...", command=self.open_format).pack(side="left", padx=6)
        ttk.Label(top, text="Byte order:").pack(side="left", padx=(12, 4))
        self.byte_order_combo = ttk.Combobox(
            top, state="readonly", width=12,
            textvariable=self.byte_order_var,
            values=("MSB-first", "LSB-first"))
        self.byte_order_combo.pack(side="left")
        self.byte_order_combo.bind("<<ComboboxSelected>>",
                                   lambda _event: self.schedule_parse())
        ttk.Button(top, text="Load file...", command=self.load_file).pack(side="right")
        ttk.Button(top, text="Clear", command=self.clear_all).pack(side="right", padx=6)

        filters = ttk.Frame(root, padding=(8, 0, 8, 4))
        filters.pack(fill="x")
        ttk.Label(filters, text="Search:").pack(side="left")
        search = ttk.Entry(filters, textvariable=self.search_var, width=30)
        self.search_entry = search
        search.pack(side="left", padx=6)
        search.bind("<KeyRelease>", lambda _event: self.schedule_parse())
        search.bind("<Return>", lambda _event: self.parse())
        ttk.Button(filters, text="Clear search", command=self.clear_search).pack(side="left")
        ttk.Checkbutton(filters, text="Anomalies only",
                        variable=self.anomalies_only_var,
                        command=self.parse).pack(side="left", padx=12)
        ttk.Button(filters, text="Next anomaly", command=self.next_anomaly).pack(side="right")

        self.status = ttk.Label(root, anchor="w", padding=(8, 3), relief="sunken")
        self.status.pack(fill="x", side="bottom")

        self.legend = ttk.Frame(root, padding=(8, 0, 8, 4))
        self.legend.pack(fill="x")

        pane = ttk.PanedWindow(root, orient="vertical")
        pane.pack(fill="both", expand=True, padx=8)

        inframe = ttk.LabelFrame(pane, text="Hex input (whitespace, 0x, commas ignored)")
        pane.add(inframe, weight=1)
        self.input = tk.Text(inframe, height=8, font=("TkFixedFont",), wrap="none", undo=True)
        inscroll = ttk.Scrollbar(inframe, orient="vertical", command=self.input.yview)
        inhscroll = ttk.Scrollbar(inframe, orient="horizontal", command=self.input.xview)
        self.input.configure(yscrollcommand=inscroll.set)
        self.input.configure(xscrollcommand=inhscroll.set)
        inscroll.pack(side="right", fill="y")
        inhscroll.pack(side="bottom", fill="x")
        self.input.pack(fill="both", expand=True, padx=4, pady=4)
        self.input.bind("<<Modified>>", self.on_modified)
        self.install_input_bindings()

        outframe = ttk.LabelFrame(pane, text="Decoded words")
        pane.add(outframe, weight=3)
        ttk.Style(root).configure("Treeview", font=("TkFixedFont",))
        self.tree = ttk.Treeview(outframe, show="headings")
        vsb = ttk.Scrollbar(outframe, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(outframe, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        outframe.rowconfigure(0, weight=1)
        outframe.columnconfigure(0, weight=1)
        self.tree.tag_configure("stripe", background=self.TAG_STRIPE)

        for path in discover_formats():
            try:
                self.add_format(load_format(path))
            except FormatError as e:
                print("hextract: skipping %s: %s" % (path, e), file=sys.stderr)
        names = list(self.formats)
        if names:
            self.combo.set(names[0])
            self.on_format_change()
        else:
            self.build_columns()
            self.set_status("no formats found in %s" % FORMATS_DIR)

    def add_format(self, fmt):
        self.formats[fmt.name] = fmt
        self.combo.configure(values=list(self.formats))

    def current(self):
        name = self.combo.get()
        return self.formats.get(name)

    def on_format_change(self, _event=None):
        fmt = self.current()
        if fmt is None:
            return
        self.byte_order_var.set("MSB-first" if fmt.byte_order == "msb-first"
                                else "LSB-first")
        for i, rule in enumerate(fmt.rules):
            kw = {}
            if rule.bg:
                kw["background"] = rule.bg
            if rule.fg:
                kw["foreground"] = rule.fg
            self.tree.tag_configure("rule%d" % i, **kw)
        self.update_legend(fmt)
        self.build_columns()
        self.parse()
        self.set_status("format: %s - %s" % (fmt.name, fmt.description))

    def open_format(self):
        path = filedialog.askopenfilename(
            title="Open format description",
            filetypes=[("TOML formats", "*.toml"), ("all files", "*")])
        if not path:
            return
        try:
            fmt = load_format(path)
        except FormatError as e:
            self.set_status("format error: %s" % e)
            return
        self.add_format(fmt)
        self.combo.set(fmt.name)
        self.on_format_change()

    def build_columns(self):
        fmt = self.current()
        cols = ["#", "status"] + (fmt.columns() if fmt else [])
        self.tree["columns"] = cols
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=50 if c == "#" else (120 if c == "status" else 96),
                             anchor="center" if c == "#" else "e", stretch=False)

    def on_modified(self, _event=None):
        if self.input.edit_modified():
            self.input.edit_modified(False)
            self.schedule_parse()

    def install_input_bindings(self):
        bindings = {
            "<Control-a>": self.select_all_input,
            "<Control-c>": self.copy_input,
            "<Control-x>": self.cut_input,
            "<Control-v>": self.paste_input,
            "<Control-z>": self.undo_input,
            "<Control-y>": self.redo_input,
            "<Control-Shift-Z>": self.redo_input,
            "<Control-f>": self.focus_search,
        }
        for sequence, callback in bindings.items():
            self.input.bind(sequence, callback)

        self.input_menu = tk.Menu(self.input, tearoff=False)
        self.input_menu.add_command(label="Select all", command=self.select_all_input)
        self.input_menu.add_separator()
        self.input_menu.add_command(label="Undo", command=self.undo_input)
        self.input_menu.add_command(label="Redo", command=self.redo_input)
        self.input_menu.add_separator()
        self.input_menu.add_command(label="Cut", command=self.cut_input)
        self.input_menu.add_command(label="Copy", command=self.copy_input)
        self.input_menu.add_command(label="Paste", command=self.paste_input)
        self.input.bind("<Button-3>", self.show_input_menu)

    def select_all_input(self, _event=None):
        self.input.focus_set()
        self.input.tag_add(tk.SEL, "1.0", "end-1c")
        self.input.mark_set(tk.INSERT, "end-1c")
        return "break"

    def undo_input(self, _event=None):
        try:
            self.input.edit_undo()
        except tk.TclError:
            pass
        return "break"

    def copy_input(self, _event=None):
        self.input.event_generate("<<Copy>>")
        return "break"

    def cut_input(self, _event=None):
        self.input.event_generate("<<Cut>>")
        return "break"

    def paste_input(self, _event=None):
        self.input.event_generate("<<Paste>>")
        return "break"

    def redo_input(self, _event=None):
        try:
            self.input.edit_redo()
        except tk.TclError:
            pass
        return "break"

    def focus_search(self, _event=None):
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, "end")
        return "break"

    def show_input_menu(self, event):
        self.input.focus_set()
        self.input_menu.tk_popup(event.x_root, event.y_root)
        return "break"

    def schedule_parse(self):
        if self._debounce is not None:
            self.root.after_cancel(self._debounce)
        self._debounce = self.root.after(150, self.parse)

    def load_file(self):
        path = filedialog.askopenfilename(
            title="Load hex capture",
            filetypes=[("text files", "*.txt *.csv *.log"), ("all files", "*")])
        if not path:
            return
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
        self.input.delete("1.0", "end")
        self.input.insert("1.0", text)
        self.parse()

    def clear_all(self):
        self.input.delete("1.0", "end")
        self.parse()

    def clear_search(self):
        self.search_var.set("")
        self.parse()

    def next_anomaly(self):
        if not self._anomaly_items:
            self.set_status("no visible anomalies")
            return
        selected = self.tree.selection()
        current = selected[0] if selected else None
        try:
            pos = self._anomaly_items.index(current)
            item = self._anomaly_items[(pos + 1) % len(self._anomaly_items)]
        except ValueError:
            item = self._anomaly_items[0]
        self.tree.selection_set(item)
        self.tree.focus(item)
        self.tree.see(item)

    def update_legend(self, fmt):
        for child in self.legend.winfo_children():
            child.destroy()
        if not fmt.rules:
            return
        ttk.Label(self.legend, text="Rules:").pack(side="left", padx=(0, 6))
        for i, rule in enumerate(fmt.rules):
            label = tk.Label(self.legend, text=" %s " % rule_display_name(rule, i),
                             background=rule.bg or "white",
                             foreground=rule.fg or "black",
                             relief="solid", borderwidth=1, padx=3, pady=1)
            label.pack(side="left", padx=2)

    def set_status(self, msg):
        self.status.configure(text=msg)

    def parse(self):
        self.build_columns()
        self.tree.delete(*self.tree.get_children())
        fmt = self.current()
        if fmt is None:
            self.set_status("no format selected")
            return

        rows, rem, err = hex_to_words(
            self.input.get("1.0", "end"), fmt,
            self.byte_order_var.get() == "MSB-first")
        if err:
            self.set_status("error: %s" % err)
            return

        self._anomaly_items = []
        query = self.search_var.get().strip().casefold()
        shown = 0
        error_rows = 0
        for idx, row in enumerate(rows):
            matched, errors = evaluate_row(fmt, row)
            if errors:
                error_rows += 1
            anomaly = matched is not None and fmt.rules[matched].bg is not None
            status = ("! " + rule_display_name(fmt.rules[matched], matched)
                      if anomaly else "-" if matched is not None else "")
            vals = [idx, status]
            for f in fmt.fields:
                v = row[f.name]
                if f.count == 1:
                    vals.append(format_cell(f, v))
                else:
                    vals.extend(format_cell(f, x) for x in v)
            haystack = " ".join(str(value) for value in vals).casefold()
            if (self.anomalies_only_var.get() and not anomaly) or (query and query not in haystack):
                continue
            if shown >= self.MAX_GUI_ROWS:
                continue
            item = self.tree.insert("", "end", values=vals, tags=row_tags(fmt, row, idx))
            shown += 1
            if anomaly:
                self._anomaly_items.append(item)

        msg = "%d words x %d B (%s), showing %d" % (
            len(rows), fmt.word_bytes, fmt.name, shown)
        if len(rows) > shown and shown == self.MAX_GUI_ROWS:
            msg += " (display limit %d)" % self.MAX_GUI_ROWS
        if error_rows:
            msg += ", %d rule evaluation errors" % error_rows
        if fmt.rule_warnings:
            msg += "; warning: " + "; ".join(fmt.rule_warnings)
        if rem:
            msg += " + %d trailing bytes ignored" % rem
        self.set_status(msg)


def gui_main():
    if not HAVE_TK:
        sys.exit("hextract: tkinter is not available on this system")
    root = tk.Tk()
    root.geometry("1100x700")
    App(root)
    root.mainloop()


# ---------------------------------------------------------------- entry

def main(argv=None):
    if tomllib is None:
        sys.exit("hextract: TOML formats need Python >= 3.11 (tomllib); running %s"
                 % sys.version.split()[0])

    parser = argparse.ArgumentParser(
        prog="hextract",
        description="Decode hex word dumps using a TOML format description.")
    parser.add_argument("-f", "--format", metavar="NAME_OR_PATH",
                        help="format name (from formats/) or path to a .toml")
    parser.add_argument("input", nargs="?",
                        help="hex capture file (default: stdin)")
    parser.add_argument("--list-formats", action="store_true",
                        help="list bundled format files and exit")
    parser.add_argument("--no-header", action="store_true",
                        help="suppress the column header in CLI output")
    args = parser.parse_args(argv)

    if args.list_formats:
        return cli_list_formats()

    if args.format:
        try:
            fmt = resolve_format(args.format)
        except FormatError as e:
            print("hextract: %s" % e, file=sys.stderr)
            return 2
        try:
            if args.input:
                with open(args.input, "r", errors="replace") as fh:
                    text = fh.read()
            else:
                text = sys.stdin.read()
        except OSError as e:
            print("hextract: %s" % e, file=sys.stderr)
            return 1
        return cli_decode(fmt, text, args.no_header)

    if sys.stdin.isatty():
        gui_main()
        return 0
    sys.exit("hextract: nothing to do - pass -f FORMAT for CLI mode")


if __name__ == "__main__":
    sys.exit(main())
