"""Enforce the package-level justification for the scoped OpenPGP exception."""

import pathlib
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_imports.py GO_LIST_OUTPUT")
    packages = [line for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    if not packages:
        raise SystemExit("empty Go dependency inventory")
    forbidden = "golang.org/x/crypto/openpgp"
    matches = [line for line in packages if line.split()[0] == forbidden
               or line.split()[0].startswith(forbidden + "/")]
    if matches:
        raise SystemExit("unmaintained OpenPGP package imported: " + ", ".join(matches))
    print("OpenPGP import prohibition verified")


if __name__ == "__main__":
    main()
