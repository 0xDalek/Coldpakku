#!/usr/bin/env python3
"""Genera src/bip39_wordlist.h a partir del fichero oficial english.txt.

Uso:
    python3 tools/gen_wordlist.py third_party/bip39-wordlist.txt src/bip39_wordlist.h
"""
import sys
from pathlib import Path


def main(src: str, dst: str) -> int:
    words = Path(src).read_text(encoding="utf-8").strip().split("\n")
    if len(words) != 2048:
        print(f"ERROR: esperaba 2048 palabras, encontradas {len(words)}", file=sys.stderr)
        return 1

    if words != sorted(words):
        print("ERROR: la wordlist BIP39 oficial debe estar ordenada alfabéticamente",
              file=sys.stderr)
        return 1

    out = []
    out.append("/* Generado por tools/gen_wordlist.py — NO EDITAR A MANO */")
    out.append("#ifndef BIP39_WORDLIST_H")
    out.append("#define BIP39_WORDLIST_H")
    out.append("")
    out.append("#define BIP39_WORDLIST_LEN 2048")
    out.append("")
    out.append("static const char* const BIP39_WORDS[BIP39_WORDLIST_LEN] = {")
    for i in range(0, 2048, 8):
        chunk = ", ".join(f'"{w}"' for w in words[i:i + 8])
        out.append(f"    {chunk},")
    out.append("};")
    out.append("")
    out.append("#endif /* BIP39_WORDLIST_H */")
    out.append("")

    Path(dst).write_text("\n".join(out), encoding="utf-8")
    print(f"escritas {len(words)} palabras en {dst}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
