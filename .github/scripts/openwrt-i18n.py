#!/usr/bin/env python3
"""Translations of the OpenWrt web plugin (apps/mesh-node/openwrt).

  openwrt-i18n.py check APP_DIR
      Every string the plugin translates (`_('…')` in the views, menu titles)
      has exactly one non-empty translation in every po/<lang>/*.po, the
      template po/templates/*.pot lists the same strings, and no catalog has
      entries the plugin no longer uses.

  openwrt-i18n.py lmo PO OUT
      Writes the binary catalog the web interface loads (.lmo). Same layout
      and hash as the upstream po2lmo tool, see lmo_write() below.

  openwrt-i18n.py ucode-check PO
      Prints a ucode script that checks every translation of PO through the
      web interface's catalog loader on an OpenWrt system.

  openwrt-i18n.py hash TEXT...
      Prints the key hash of each argument; CI compares it with the upstream
      C function (.github/workflows/openwrt.yml).
"""

import glob
import json
import os
import re
import struct
import sys

STRING = re.compile(r"_\('((?:[^'\\]|\\.)*)'\)")
MASK = 0xFFFFFFFF


def sfh_hash(data: bytes, init: int) -> int:
    """Paul Hsieh's SuperFastHash as in luci-base lib/lmo.c (sfh_hash)."""

    def get16(i):
        return data[i] | (data[i + 1] << 8)

    def signed(byte):
        return byte - 256 if byte > 127 else byte

    length = len(data)
    if length == 0:
        return 0
    h = init & MASK
    rem = length & 3
    i = 0
    for _ in range(length >> 2):
        h = (h + get16(i)) & MASK
        tmp = ((get16(i + 2) << 11) ^ h) & MASK
        h = ((h << 16) ^ tmp) & MASK
        i += 4
        h = (h + (h >> 11)) & MASK
    if rem == 3:
        h = (h + get16(i)) & MASK
        h ^= (h << 16) & MASK
        h ^= (signed(data[i + 2]) << 18) & MASK
        h = (h + (h >> 11)) & MASK
    elif rem == 2:
        h = (h + get16(i)) & MASK
        h ^= (h << 11) & MASK
        h = (h + (h >> 17)) & MASK
    elif rem == 1:
        h = (h + signed(data[i])) & MASK
        h ^= (h << 10) & MASK
        h = (h + (h >> 1)) & MASK
    h ^= (h << 3) & MASK
    h = (h + (h >> 5)) & MASK
    h ^= (h << 4) & MASK
    h = (h + (h >> 17)) & MASK
    h ^= (h << 25) & MASK
    h = (h + (h >> 6)) & MASK
    return h


def unquote(line: str, prefix: str) -> str:
    rest = line[len(prefix):].strip()
    if len(rest) < 2 or rest[0] != '"' or rest[-1] != '"':
        raise ValueError(f"malformed line: {line!r}")
    body = rest[1:-1]
    # The catalogs here use no escapes at all; header lines end in \n.
    if '"' in body.replace('\\"', ""):
        raise ValueError(f"unescaped quote: {line!r}")
    return body


def read_po(path: str):
    """Returns (header, {msgid: msgstr}) for a po file without plurals or
    contexts (the plugin uses neither)."""
    entries = {}
    header = None
    msgid = msgstr = None
    current = None

    def flush():
        nonlocal header
        if msgid is None:
            return
        if msgid == "":
            header = msgstr
        elif msgid in entries:
            raise ValueError(f"{path}: duplicate msgid {msgid!r}")
        else:
            entries[msgid] = msgstr

    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if line.startswith("#") or not line.strip():
                continue
            if line.startswith(("msgctxt", "msgid_plural", "msgstr[")):
                raise ValueError(f"{path}: contexts and plurals are not used: {line!r}")
            if line.startswith("msgid "):
                flush()
                msgid, msgstr, current = unquote(line, "msgid"), None, "id"
            elif line.startswith("msgstr "):
                msgstr, current = unquote(line, "msgstr"), "str"
            elif line.startswith('"'):
                part = unquote(line, "")
                if current == "id":
                    msgid += part
                elif current == "str":
                    msgstr += part
                else:
                    raise ValueError(f"{path}: continuation without field: {line!r}")
            else:
                raise ValueError(f"{path}: unexpected line: {line!r}")
        flush()
    return header, entries


def plugin_strings(app_dir: str):
    found = []
    for path in sorted(glob.glob(os.path.join(app_dir, "htdocs", "**", "*.js"), recursive=True)):
        with open(path, encoding="utf-8") as handle:
            for match in STRING.finditer(handle.read()):
                text = match.group(1)
                if "\\" in text:
                    raise ValueError(f"{path}: escapes are not supported in translated strings: {text!r}")
                if text not in found:
                    found.append(text)
    for path in sorted(glob.glob(os.path.join(app_dir, "root", "usr", "share", "luci", "menu.d", "*.json"))):
        with open(path, encoding="utf-8") as handle:
            for node in json.load(handle).values():
                title = node.get("title")
                if title and title not in found:
                    found.append(title)
    return found


def canonical(text: str) -> bool:
    # The web interface collapses white space before hashing a key
    # (lmo_canon_hash); keys must already be in that form.
    return text == " ".join(text.split())


def check(app_dir: str) -> int:
    errors = []
    wanted = plugin_strings(app_dir)
    if not wanted:
        errors.append("no translated strings found")
    for text in wanted:
        if not canonical(text):
            errors.append(f"string is not in canonical white-space form: {text!r}")
    wanted_set = set(wanted)

    templates = glob.glob(os.path.join(app_dir, "po", "templates", "*.pot"))
    catalogs = glob.glob(os.path.join(app_dir, "po", "*", "*.po"))
    if len(templates) != 1:
        errors.append(f"expected one template, found {templates}")
    if not catalogs:
        errors.append("no catalogs under po/<lang>/")
    for path in templates + catalogs:
        try:
            header, entries = read_po(path)
        except ValueError as error:
            errors.append(str(error))
            continue
        if header is None or "charset=UTF-8" not in header:
            errors.append(f"{path}: header must declare charset=UTF-8")
        missing = sorted(wanted_set - entries.keys())
        stale = sorted(entries.keys() - wanted_set)
        for text in missing:
            errors.append(f"{path}: missing {text!r}")
        for text in stale:
            errors.append(f"{path}: not used by the plugin {text!r}")
        if path.endswith(".po"):
            for text, value in entries.items():
                if not value:
                    errors.append(f"{path}: empty translation for {text!r}")
                elif "\\" in value:
                    errors.append(f"{path}: escapes are not supported: {value!r}")
    for error in errors:
        print(f"::error::{error}")
    if errors:
        return 1
    print(f"{len(wanted)} strings, {len(catalogs)} catalog(s): complete")
    return 0


def lmo_write(po_path: str, out_path: str) -> None:
    """Layout written by luci-base src/po2lmo.c: the translations, each
    padded to 4 bytes; then the index sorted by key hash, 16 bytes per entry
    (key hash, value id, offset, length, big-endian); then the index offset.
    The Plural-Forms header has key and value id 0. An entry whose value
    hashes like its key (untranslated) is left out."""
    header, entries = read_po(po_path)
    blob = bytearray()
    index = []

    def add(key_id, val_id, value: bytes):
        index.append((key_id, val_id, len(blob), len(value)))
        blob.extend(value)
        blob.extend(b"\0" * ((4 - len(value) % 4) % 4))

    if header:
        for field in header.split("\\n"):
            if field.lower().startswith("plural-forms: "):
                add(0, 0, field[len("plural-forms: "):].encode("utf-8"))
                break
    for msgid, msgstr in entries.items():
        if not msgstr:
            continue
        key = msgid.encode("utf-8")
        value = msgstr.encode("utf-8")
        key_id = sfh_hash(key, len(key))
        if key_id == sfh_hash(value, len(value)):
            continue
        add(key_id, 1, value)
    keys = [entry[0] for entry in index]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{po_path}: two strings share a hash")
    index.sort(key=lambda entry: entry[0])
    offset = len(blob)
    for entry in index:
        blob.extend(struct.pack(">IIII", *entry))
    blob.extend(struct.pack(">I", offset))
    with open(out_path, "wb") as handle:
        handle.write(blob)


def hashes(texts) -> int:
    """Prints sfh_hash(text, len) per argument, for comparison with the
    upstream C function in CI."""
    for text in texts:
        data = text.encode("utf-8")
        print(f"{sfh_hash(data, len(data)):08x}")
    return 0


def ucode_check(po_path: str) -> int:
    """Prints a ucode script that loads the installed catalogs with the web
    interface's own loader (luci.core) and checks every translation."""
    _, entries = read_po(po_path)
    pairs = json.dumps(sorted(entries.items()), ensure_ascii=False)
    print("import { load_catalog, change_catalog, translate } from 'luci.core';")
    print("if (!load_catalog('zh-cn', '/usr/lib/lua/luci/i18n')) die('catalog not loaded');")
    print("change_catalog('zh-cn');")
    print("let bad = 0;")
    print(f"for (let pair in {pairs}) {{")
    print("\tif (translate(pair[0]) != pair[1]) {")
    print("\t\twarn('not translated: ' + pair[0] + '\\n');")
    print("\t\tbad++;")
    print("\t}")
    print("}")
    print(f"print('{len(entries)} translations checked\\n');")
    print("exit(bad ? 1 : 0);")
    return 0


def main(argv) -> int:
    if len(argv) == 3 and argv[1] == "check":
        return check(argv[2])
    if len(argv) == 4 and argv[1] == "lmo":
        lmo_write(argv[2], argv[3])
        return 0
    if len(argv) == 3 and argv[1] == "ucode-check":
        return ucode_check(argv[2])
    if len(argv) >= 3 and argv[1] == "hash":
        return hashes(argv[2:])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
