import argparse
import hashlib
import json
import os
import sys
from datetime import datetime

DEFAULT_BASELINE = "baseline.json"
DEFAULT_EXCLUDES = {".git", "__pycache__", ".vscode", "node_modules"}


def sha256_file(path, chunk_size=65536):
    """Hitung hash SHA-256 file, dibaca per potongan agar hemat memori."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk_size), b""):
            h.update(block)
    return h.hexdigest()


def scan(target, excludes, skip_files=()):
    """Telusuri folder, kembalikan dict {path_relatif: info_file}."""
    target = os.path.abspath(target)
    skip = {os.path.abspath(p) for p in skip_files}
    result = {}
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in excludes]
        for name in files:
            full = os.path.abspath(os.path.join(root, name))
            if name in excludes or full in skip:
                continue
            rel = os.path.relpath(full, target).replace(os.sep, "/")
            try:
                result[rel] = {
                    "sha256": sha256_file(full),
                    "size": os.path.getsize(full),
                }
            except (OSError, PermissionError) as e:
                print(f"[!] Dilewati {rel}: {e}", file=sys.stderr)
    return result


def cmd_init(args):
    if not os.path.isdir(args.folder):
        sys.exit(f"Folder tidak ditemukan: {args.folder}")
    excludes = DEFAULT_EXCLUDES | set(args.exclude or [])
    files = scan(args.folder, excludes, skip_files=[args.baseline])
    data = {
        "target": os.path.abspath(args.folder),
        "created": datetime.now().isoformat(timespec="seconds"),
        "excludes": sorted(excludes),
        "files": files,
    }
    with open(args.baseline, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Baseline dibuat: {len(files)} file tercatat -> {args.baseline}")


def cmd_check(args):
    try:
        with open(args.baseline) as f:
            base = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"Gagal membaca baseline: {e}")

    folder = args.folder or base["target"]
    if not os.path.isdir(folder):
        sys.exit(f"Folder tidak ditemukan: {folder}")

    old = base["files"]
    new = scan(folder, set(base["excludes"]), skip_files=[args.baseline])

    added = sorted(set(new) - set(old))
    deleted = sorted(set(old) - set(new))
    modified = sorted(p for p in set(old) & set(new) if old[p]["sha256"] != new[p]["sha256"])

    print("=" * 60)
    print(" FILE INTEGRITY MONITOR - LAPORAN")
    print("=" * 60)
    print(f"Folder          : {folder}")
    print(f"Baseline dibuat : {base['created']}")
    print(f"File di baseline: {len(old)}  |  File sekarang: {len(new)}\n")

    for label, items in (("DITAMBAH", added), ("DIUBAH", modified), ("DIHAPUS", deleted)):
        if items:
            print(f"[{label}] ({len(items)})")
            for p in items:
                extra = ""
                if label == "DIUBAH":
                    extra = f"  {old[p]['sha256'][:12]}... -> {new[p]['sha256'][:12]}..."
                print(f"   - {p}{extra}")
            print()

    if not (added or modified or deleted):
        print("Tidak ada perubahan. Semua file sesuai baseline.")
        return 0

    print("Perubahan terdeteksi. Periksa apakah ini perubahan yang kamu lakukan sendiri.")
    return 1


def main():
    p = argparse.ArgumentParser(description="File Integrity Monitor berbasis hash SHA-256.")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", help="buat baseline dari sebuah folder")
    pi.add_argument("folder")
    pi.add_argument("-b", "--baseline", default=DEFAULT_BASELINE)
    pi.add_argument("-x", "--exclude", nargs="*", help="nama file/folder tambahan yang diabaikan")
    pi.set_defaults(func=cmd_init)

    pc = sub.add_parser("check", help="bandingkan folder dengan baseline")
    pc.add_argument("folder", nargs="?", help="default: folder yang tercatat di baseline")
    pc.add_argument("-b", "--baseline", default=DEFAULT_BASELINE)
    pc.set_defaults(func=cmd_check)

    args = p.parse_args()
    code = args.func(args)
    sys.exit(code or 0)


if __name__ == "__main__":
    main()