#!/usr/bin/env python3
"""Build release ZIP from include_files.txt

Usage: python scripts/build_release_package.py artifacts/app-<tag>.zip [include_files.txt]
"""
import os
import sys
import zipfile


def main():
    if len(sys.argv) < 2:
        print("Usage: build_release_package.py <out_zip> [include_files.txt]", file=sys.stderr)
        return 2
    out_zip = sys.argv[1]
    include_file = sys.argv[2] if len(sys.argv) > 2 else "include_files.txt"

    if not os.path.exists(include_file):
        print(f"Include file not found: {include_file}", file=sys.stderr)
        return 1

    with open(include_file, "r", encoding="utf-8") as fh:
        files = [l.strip() for l in fh if l.strip()]

    os.makedirs(os.path.dirname(out_zip) or ".", exist_ok=True)

    written = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in files:
            if os.path.isfile(p):
                zf.write(p, arcname=p)
                written += 1
            elif os.path.isdir(p):
                # add directory contents recursively
                for root, dirs, filenames in os.walk(p):
                    for fn in filenames:
                        fp = os.path.join(root, fn)
                        arc = os.path.relpath(fp)
                        zf.write(fp, arcname=arc)
                        written += 1
            else:
                # skip missing/submodule paths
                print(f"Skipping non-file/non-dir: {p}")

    print(f"Wrote {written} files to {out_zip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
