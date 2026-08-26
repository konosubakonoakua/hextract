# hextract

Format-driven decoder for hex word dumps (Vivado ILA captures, BRAM dumps,
...). Packet layouts are declared in TOML files instead of code, so the same
tool works for any project's word width and fields.

Single file, stdlib only, Python >= 3.11 (tomllib). The CLI works without
tkinter/DISPLAY.

## Usage

```bash
./hextract.py                              # tkinter GUI (formats/ auto-discovered)
./hextract.py -f blm_interlock_512 cap.txt # CLI decode from file
./hextract.py -f blm_interlock_512 < cap.txt
./hextract.py --list-formats
```

`-f` takes a bundled format name (from `formats/`) or a path to any `.toml`.
In the GUI paste hex (whitespace/`0x`/commas are ignored); the table updates
as you type. Use `New tab` to open another independent data workspace: each
tab keeps its own format, byte order, input, filters, and decoded table, so
different captures can be compared side by side. `Open format...` adds a TOML
format to the shared format list, and `Close tab` removes the current workspace.
Byte order defaults per format (`msb-first` reverses each word's bytes, which
is what ILA's MSB-first display needs).

## TOML schema

```toml
[format]
name = "my_packet"          # required, unique
description = "..."
word_bits = 256             # required, multiple of 8
byte_order = "msb-first"    # or "lsb-first" (default msb-first)

[[field]]                   # order = packet layout, LSB end first
name = "integral"
type = "i16"                # u8..u64 i8..i64 f32 f64
count = 6                   # optional -> columns integral0..integral5
bits = "3:0"                # optional bitfield; int = single bit
radix = "hex"               # optional display radix (hex/dec)
scale = 100.0               # optional display multiplier

[[rule]]                    # row coloring, first match wins (GUI)
name = "negative integral" # optional legend/status name
when = "any(v < 0 for v in integral)"
bg = "#f6caca"              # bg and/or fg
```

Fields may use fewer bits than `word_bits`; the remainder is padding.
`when` is a restricted Python expression over field names (arrays stay
tuples); allowed calls: `any all min max abs len`.

The GUI shows a rule legend and a status column, supports text search, an
anomalies-only filter, and a next-anomaly action. Rows with a matching rule
are never given the zebra stripe, so rule colors remain visible. The display
is limited to 10,000 rows to keep the interface responsive; the status bar
reports truncation and rule evaluation errors. Duplicate rule expressions are
reported as warnings because the first matching rule wins.

The Hex input supports standard editing shortcuts: Ctrl+A selects all, Ctrl+C
copies, Ctrl+X cuts, Ctrl+V pastes, Ctrl+Z undoes, Ctrl+Y (or Ctrl+Shift+Z)
redoes, and Ctrl+F focuses the search box. Right-clicking the input opens the
same editing actions in a context menu.

Optional Vim mode can be enabled in the GUI. It starts in INSERT mode; press
Esc for NORMAL mode. The initial NORMAL commands are `i`, `a`, `o`, `h`, `j`,
`k`, `l`, `x`, `dd`, `yy`, `p`, `0`, and `$`. `dd` and `yy` use an internal
line register, and `p` pastes that line below the current line. Ctrl+U deletes
from the cursor to the beginning of the current line in either mode.

## Bundled formats

| file | packet | layout |
|---|---|---|
| `blm_rawdata_256.toml` | `bram_rawdata_packet` (32 B) | wr_time_s/ns, i16 integral[6], u16 count[6] |
| `blm_interlock_512.toml` | `bram_interlock_packet` (64 B) | + data_id, locked_bram_addr; i32/u32 |

Both must stay in sync with `blmApp/src/blmPLRegDefs.h`.

## Tests

```bash
python3 -m unittest test_hextract -v
```
