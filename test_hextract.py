#!/usr/bin/env python3
"""Unit tests for hextract.py. Run: python3 -m unittest test_hextract -v"""

import os
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hextract as hx

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "hextract.py")
FMT512 = os.path.join(HERE, "formats", "blm_interlock_512.toml")
FMT256 = os.path.join(HERE, "formats", "blm_rawdata_256.toml")


def msbfirst(blob, word_bytes):
    """Reorder a little-endian byte stream into per-word MSB-first (ILA) order."""
    return b"".join(blob[i:i + word_bytes][::-1]
                    for i in range(0, len(blob), word_bytes))


def interlock_blob():
    pkts = b""
    pkts += struct.pack('<IIII6i6I', 100, 200, 1, 0xabc, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0)
    pkts += struct.pack('<IIII6i6I', 100, 200, 2, 0xabc, -5, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0)
    pkts += struct.pack('<IIII6i6I', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return pkts


class TestBundledFormats(unittest.TestCase):
    def test_interlock_512(self):
        fmt = hx.load_format(FMT512)
        self.assertEqual(fmt.word_bytes, 64)
        self.assertEqual(fmt.columns()[:4], ["wr_time_s", "wr_time_ns", "data_id", "lock_addr"])
        self.assertEqual(fmt.columns()[4:10], ["integral%d" % i for i in range(6)])
        rows, rem, err = hx.hex_to_words(msbfirst(interlock_blob(), 64).hex(), fmt)
        self.assertIsNone(err)
        self.assertEqual(rem, 0)
        self.assertEqual(len(rows), 3)
        r0 = rows[0]
        self.assertEqual(r0["wr_time_s"], 100)
        self.assertEqual(r0["wr_time_ns"], 200)
        self.assertEqual(r0["data_id"], 1)
        self.assertEqual(r0["lock_addr"], 0xabc)
        self.assertEqual(r0["integral"], (1, 2, 3, 4, 5, 6))
        self.assertEqual(r0["count"], (7, 0, 0, 0, 0, 0))
        self.assertEqual(rows[1]["integral"][0], -5)

    def test_reverse_override(self):
        fmt = hx.load_format(FMT512)
        blob = interlock_blob()[:64]
        rows, _, err = hx.hex_to_words(blob.hex(), fmt, reverse=False)
        self.assertIsNone(err)
        self.assertEqual(rows[0]["wr_time_s"], 100)
        rows, _, err = hx.hex_to_words(blob.hex(), fmt, reverse=True)
        self.assertIsNone(err)
        self.assertNotEqual(rows[0]["wr_time_s"], 100)

    def test_rawdata_256(self):
        fmt = hx.load_format(FMT256)
        self.assertEqual(fmt.word_bytes, 32)
        blob = struct.pack('<II6h6H', 1, 2, 1, 2, 3, 4, 5, 6, 9, 0, 0, 0, 0, 0)
        rows, rem, err = hx.hex_to_words(blob.hex(), fmt)
        self.assertIsNone(err)
        self.assertEqual(rem, 0)
        self.assertEqual(rows[0]["wr_time_ns"], 2)
        self.assertEqual(rows[0]["integral"], (1, 2, 3, 4, 5, 6))
        self.assertEqual(rows[0]["count"][0], 9)

    def test_hex_radix_cell(self):
        fmt = hx.load_format(FMT512)
        f = [f for f in fmt.fields if f.name == "data_id"][0]
        self.assertEqual(hx.format_cell(f, 0xabc), "0xabc")
        self.assertEqual(hx.format_cell(f, -1), "-0x1")


class TestDecodeErrors(unittest.TestCase):
    def setUp(self):
        self.fmt = hx.load_format(FMT512)

    def test_odd_hex(self):
        _, _, err = hx.hex_to_words("abc", self.fmt)
        self.assertEqual(err, "odd number of hex characters")

    def test_partial_word(self):
        rows, rem, err = hx.hex_to_words("00" * 63, self.fmt)
        self.assertIn("need 64 B", err)
        self.assertEqual(rem, 63)
        self.assertEqual(rows, [])

    def test_trailing_bytes(self):
        hxtext = msbfirst(interlock_blob(), 64).hex() + "deadbeef"
        rows, rem, err = hx.hex_to_words(hxtext, self.fmt)
        self.assertIsNone(err)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rem, 4)

    def test_empty(self):
        rows, rem, err = hx.hex_to_words("  \n", self.fmt)
        self.assertEqual((rows, rem, err), ([], 0, None))

    def test_noise_stripped(self):
        blob = interlock_blob()[:64]
        hxtext = "0x" + msbfirst(blob, 64).hex()[:8] + ", " + msbfirst(blob, 64).hex()[8:]
        rows, _, err = hx.hex_to_words(hxtext, self.fmt)
        self.assertIsNone(err)
        self.assertEqual(rows[0]["wr_time_s"], 100)


BF_TOML = """
[format]
name = "bf"
word_bits = 32
byte_order = "lsb-first"

[[field]]
name = "flag7"
type = "u8"
bits = 7

[[field]]
name = "nib"
type = "u16"
bits = "3:0"

[[field]]
name = "mv"
type = "u8"
scale = 2.5
"""


class TestBitfieldsAndScale(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        self.tmp.write(BF_TOML)
        self.tmp.close()
        self.fmt = hx.load_format(self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_decode(self):
        blob = struct.pack('<BHB', 0x85, 0xabcd, 4)
        rows, _, err = hx.hex_to_words(blob.hex(), self.fmt)
        self.assertIsNone(err)
        self.assertEqual(rows[0]["flag7"], 1)
        self.assertEqual(rows[0]["nib"], 0xd)
        self.assertEqual(rows[0]["mv"], 4)

    def test_scale_format(self):
        f = self.fmt.fields[2]
        self.assertEqual(hx.format_cell(f, 4), "10")

    def test_extract_bits(self):
        self.assertEqual(hx.extract_bits(0x85, (7, 7)), 1)
        self.assertEqual(hx.extract_bits(0xabcd, (3, 0)), 0xd)
        self.assertEqual(hx.extract_bits(0xabcd, (11, 4)), 0xbc)


class TestRules(unittest.TestCase):
    def setUp(self):
        self.fmt = hx.load_format(FMT512)

    def env(self, integral, count):
        return hx.rule_env(self.fmt, {"integral": integral, "count": count})

    def test_first_match_wins(self):
        r = self.fmt.rules
        self.assertTrue(hx.eval_rule(r[0], self.env((-1, 0, 0, 0, 0, 0), (1, 0, 0, 0, 0, 0))))
        self.assertFalse(hx.eval_rule(r[0], self.env((0, 0, 0, 0, 0, 0), (1, 0, 0, 0, 0, 0))))
        self.assertTrue(hx.eval_rule(r[1], self.env((0, 0, 0, 0, 0, 0), (1, 0, 0, 0, 0, 0))))
        self.assertTrue(hx.eval_rule(r[2], self.env((0, 0, 0, 0, 0, 0), (0, 0, 0, 0, 0, 0))))

    def test_rule_color_takes_precedence_over_stripe(self):
        row = {"integral": (-1, 0, 0, 0, 0, 0),
               "count": (0, 0, 0, 0, 0, 0)}
        self.assertEqual(hx.row_tags(self.fmt, row, 0), ["rule0"])
        self.assertEqual(hx.row_tags(self.fmt, row, 1), ["rule0"])

    def test_rule_name_and_duplicate_warning(self):
        self.assertEqual(self.fmt.rules[0].name, "Rule 1")
        duplicate = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        try:
            duplicate.write('[format]\nname = "x"\nword_bits = 8\n'
                            '[[field]]\nname = "a"\ntype = "u8"\n'
                            '[[rule]]\nwhen = "a > 0"\nbg = "#ff0000"\n'
                            '[[rule]]\nwhen = "a > 0"\nbg = "#00ff00"\n')
            duplicate.close()
            fmt = hx.load_format(duplicate.name)
            self.assertEqual(len(fmt.rule_warnings), 1)
        finally:
            os.unlink(duplicate.name)

    def _reject(self, when):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
            fh.write('[format]\nname = "x"\nword_bits = 8\n[[field]]\nname = "a"\ntype = "u8"\n'
                     '[[rule]]\nwhen = "%s"\nbg = "#ff0000"\n' % when)
            path = fh.name
        try:
            with self.assertRaises(hx.FormatError):
                hx.load_format(path)
        finally:
            os.unlink(path)

    def test_rejects_import(self):
        self._reject("__import__('os')")

    def test_rejects_attribute(self):
        self._reject("a.bit_length() > 1")

    def test_rejects_private_name(self):
        self._reject("_secret > 1")

    def test_rejects_unknown_name(self):
        self._reject("nosuch < 1")


class TestFormatValidation(unittest.TestCase):
    def load(self, toml_text):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
            fh.write(toml_text)
            path = fh.name
        try:
            return hx.load_format(path)
        finally:
            os.unlink(path)

    def test_missing_format_table(self):
        with self.assertRaises(hx.FormatError):
            self.load('[[field]]\nname = "a"\ntype = "u8"\n')

    def test_unknown_type(self):
        with self.assertRaises(hx.FormatError):
            self.load('[format]\nname = "x"\nword_bits = 8\n[[field]]\nname = "a"\ntype = "u9"\n')

    def test_bad_word_bits(self):
        with self.assertRaises(hx.FormatError):
            self.load('[format]\nname = "x"\nword_bits = 7\n[[field]]\nname = "a"\ntype = "u8"\n')

    def test_overflow(self):
        with self.assertRaises(hx.FormatError):
            self.load('[format]\nname = "x"\nword_bits = 8\n'
                      '[[field]]\nname = "a"\ntype = "u16"\n')

    def test_bits_out_of_range(self):
        with self.assertRaises(hx.FormatError):
            self.load('[format]\nname = "x"\nword_bits = 16\n'
                      '[[field]]\nname = "a"\ntype = "u8"\nbits = 8\n')

    def test_padding_allowed(self):
        fmt = self.load('[format]\nname = "x"\nword_bits = 32\n'
                        '[[field]]\nname = "a"\ntype = "u8"\n')
        self.assertEqual(fmt.struct().size, 4)
        rows, _, err = hx.hex_to_words("01020304", fmt, reverse=False)
        self.assertIsNone(err)
        self.assertEqual(rows[0]["a"], 1)

    def test_raw_byte_order_is_rejected(self):
        with self.assertRaises(hx.FormatError):
            self.load('[format]\nname = "x"\nword_bits = 8\n'
                      'byte_order = "raw"\n[[field]]\nname = "a"\ntype = "u8"\n')


@unittest.skipUnless(hx.HAVE_TK and os.environ.get("DISPLAY"), "needs tkinter + DISPLAY")
class TestGui(unittest.TestCase):
    def test_smoke(self):
        import tkinter as tk
        root = tk.Tk()
        try:
            app = hx.App(root)
            app.combo.set("blm_interlock_512")
            app.on_format_change()
            app.input.insert("1.0", msbfirst(interlock_blob(), 64).hex())
            app.parse()
            kids = app.tree.get_children()
            self.assertEqual(len(kids), 3)
            self.assertEqual(len(app.tree["columns"]), 18)
            self.assertEqual(app.tree.item(kids[0], "tags")[0], "rule1")  # has count
            self.assertEqual(app.tree.item(kids[1], "tags"), ("rule0",))  # negative
            self.assertEqual(app.tree.item(kids[2], "tags")[0], "rule2")  # all zero
        finally:
            root.destroy()


class TestCli(unittest.TestCase):
    def run_tool(self, args, stdin=None):
        return subprocess.run([sys.executable, TOOL] + args, input=stdin,
                              capture_output=True, text=True, env=os.environ.copy())

    def test_list_formats(self):
        r = self.run_tool(["--list-formats"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("blm_interlock_512", r.stdout)
        self.assertIn("blm_rawdata_256", r.stdout)

    def test_decode_stdin(self):
        r = self.run_tool(["-f", "blm_interlock_512"],
                          stdin=msbfirst(interlock_blob(), 64).hex())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("wr_time_s", r.stdout)
        self.assertIn("100", r.stdout)
        self.assertEqual(len(r.stdout.strip().splitlines()), 4)  # header + 3 rows

    def test_decode_file_no_header(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(msbfirst(interlock_blob(), 64).hex())
            path = fh.name
        try:
            r = self.run_tool(["-f", FMT512, "--no-header", path])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(len(r.stdout.strip().splitlines()), 3)
        finally:
            os.unlink(path)

    def test_unknown_format(self):
        r = self.run_tool(["-f", "definitely_not_a_format"], stdin="00")
        self.assertEqual(r.returncode, 2)

    def test_bad_hex_exit_code(self):
        r = self.run_tool(["-f", "blm_interlock_512"], stdin="abc")
        self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
