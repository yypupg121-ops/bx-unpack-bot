import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import struct
import zipfile
import zlib
from pathlib import Path
from urllib.parse import urlparse

# Conservative limits. Tune only after testing in an isolated deployment.
MAX_INPUT_BYTES = 20 * 1024 * 1024
MAX_SINGLE_OUTPUT = 16 * 1024 * 1024
MAX_TOTAL_OUTPUT = 48 * 1024 * 1024
MAX_DEPTH = 5
MAX_FILES = 80
MAX_ZIP_MEMBERS = 200
MAX_STRINGS = 5000
MIN_STRING_LEN = 5

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_name(name):
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return (name or "decoded.bin")[:100]

def printable_strings(data, limit=MAX_STRINGS):
    # ASCII strings only; avoids decoding arbitrary bytes as executable content.
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)
    out = []
    for m in pat.finditer(data):
        try:
            s = m.group().decode("ascii", "replace")
            if s not in out:
                out.append(s)
            if len(out) >= limit:
                break
        except Exception:
            pass
    return out

def signatures(data):
    result = []
    if data.startswith(b"\x7fELF"):
        bits = "64-bit" if len(data) > 4 and data[4] == 2 else "32-bit" if len(data) > 4 and data[4] == 1 else "unknown bitness"
        endian = "little-endian" if len(data) > 5 and data[5] == 1 else "big-endian" if len(data) > 5 and data[5] == 2 else "unknown endian"
        machine = "unknown"
        if len(data) >= 20:
            try:
                e = "<" if data[5] == 1 else ">"
                machine_id = struct.unpack(e + "H", data[18:20])[0]
                machine = {3:"x86", 40:"ARM", 62:"x86-64", 183:"AArch64", 243:"RISC-V"}.get(machine_id, f"machine id {machine_id}")
            except Exception:
                pass
        result.append(f"ELF executable/shared-object signature ({bits}, {endian}, {machine}); not executed")
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        result.append("ZIP archive signature")
    if data.startswith(b"\x1f\x8b"):
        result.append("gzip signature")
    if data.startswith(b"BZh"):
        result.append("bzip2 signature")
    if data.startswith(b"\xfd7zXZ\x00"):
        result.append("xz signature")
    if data.startswith(b"#!"):
        result.append("Shebang header (text script)")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        result.append("PNG image signature")
    if data.startswith(b"%PDF-"):
        result.append("PDF signature")
    return result

def try_base_decodes(data):
    # Decode only if the whole trimmed payload looks like a plausible encoded blob.
    out = []
    stripped = data.strip()
    if len(stripped) < 16 or len(stripped) > MAX_SINGLE_OUTPUT * 2:
        return out
    # Ignore whitespace for base encodings, but preserve only a conservative charset.
    compact = re.sub(rb"\s+", b"", stripped)
    candidates = [
        ("Base64", compact, lambda x: base64.b64decode(x, validate=True)),
        ("Base85", compact, lambda x: base64.b85decode(x)),
        ("Ascii85", compact, lambda x: base64.a85decode(x, adobe=False)),
    ]
    for label, blob, fn in candidates:
        try:
            # Avoid treating ordinary source text as a successful decode.
            if not re.fullmatch(rb"[A-Za-z0-9+/=_-]+", blob) and label == "Base64":
                continue
            decoded = fn(blob)
            if decoded and decoded != data and len(decoded) <= MAX_SINGLE_OUTPUT:
                # Require a known signature or a meaningful printable ratio.
                printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in decoded) / max(1, len(decoded))
                if signatures(decoded) or printable > 0.80:
                    out.append((label, decoded))
        except Exception:
            pass
    # Deduplicate byte-identical results.
    seen = set()
    unique = []
    for item in out:
        digest = hashlib.sha256(item[1]).hexdigest()
        if digest not in seen:
            seen.add(digest)
            unique.append(item)
    return unique

def try_compressions(data):
    out = []
    operations = [
        ("gzip", lambda b: gzip.decompress(b)),
        ("zlib", lambda b: zlib.decompress(b)),
        ("bzip2", lambda b: bz2.decompress(b)),
        ("xz", lambda b: lzma.decompress(b)),
    ]
    for label, fn in operations:
        try:
            decoded = fn(data)
            if decoded and decoded != data and len(decoded) <= MAX_SINGLE_OUTPUT:
                out.append((label, decoded))
        except Exception:
            pass
    return out

def write_output(root, name, data, total_state):
    if len(data) > MAX_SINGLE_OUTPUT:
        return None, "skipped: single output size limit"
    if total_state["bytes"] + len(data) > MAX_TOTAL_OUTPUT:
        return None, "skipped: total output size limit"
    if total_state["files"] >= MAX_FILES:
        return None, "skipped: file count limit"
    safe = safe_name(name)
    # Avoid overwriting prior outputs.
    stem, suffix = os.path.splitext(safe)
    candidate = safe
    i = 2
    while os.path.exists(os.path.join(root, candidate)):
        candidate = f"{stem}_{i}{suffix}"
        i += 1
    path = os.path.join(root, candidate)
    with open(path, "wb") as f:
        f.write(data)
    total_state["bytes"] += len(data)
    total_state["files"] += 1
    return path, None

def analyze_file(input_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    input_path = os.path.abspath(input_path)
    with open(input_path, "rb") as f:
        initial = f.read(MAX_INPUT_BYTES + 1)
    if len(initial) > MAX_INPUT_BYTES:
        raise ValueError("Input exceeds maximum size")

    state = {"bytes": 0, "files": 0}
    queue = [(safe_name(os.path.basename(input_path)), initial, 0, "original")]
    visited = {hashlib.sha256(initial).hexdigest()}
    layers = []
    all_strings = []
    all_signatures = []
    archive_notes = []
    decoded_dir = os.path.join(out_dir, "decoded")
    os.makedirs(decoded_dir, exist_ok=True)

    while queue and len(layers) < MAX_FILES:
        name, data, depth, origin = queue.pop(0)
        digest = hashlib.sha256(data).hexdigest()
        layers.append({
            "name": name, "depth": depth, "origin": origin,
            "size": len(data), "sha256": digest,
            "signatures": signatures(data)
        })
        for sig in signatures(data):
            if sig not in all_signatures:
                all_signatures.append(sig)
        for s in printable_strings(data):
            if s not in all_strings:
                all_strings.append(s)
            if len(all_strings) >= MAX_STRINGS:
                break

        if depth >= MAX_DEPTH:
            continue

        # ZIP is inspected without extracting paths directly. Each member is read as bytes.
        if data.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    members = zf.infolist()[:MAX_ZIP_MEMBERS]
                    archive_notes.append(f"{name}: ZIP contains {len(zf.infolist())} member(s); inspected at most {MAX_ZIP_MEMBERS}.")
                    for info in members:
                        if info.is_dir():
                            continue
                        if info.file_size > MAX_SINGLE_OUTPUT:
                            archive_notes.append(f"{info.filename}: skipped (declared size exceeds limit).")
                            continue
                        try:
                            member_data = zf.read(info)
                        except Exception as e:
                            archive_notes.append(f"{info.filename}: read failed ({type(e).__name__}).")
                            continue
                        member_name = safe_name(info.filename)
                        h = hashlib.sha256(member_data).hexdigest()
                        if h not in visited and len(member_data) <= MAX_SINGLE_OUTPUT:
                            visited.add(h)
                            saved, why = write_output(decoded_dir, member_name, member_data, state)
                            if saved:
                                queue.append((os.path.basename(saved), member_data, depth + 1, f"ZIP member in {name}"))
                            elif why:
                                archive_notes.append(f"{member_name}: {why}.")
            except Exception as e:
                archive_notes.append(f"{name}: ZIP parse failed ({type(e).__name__}).")

        candidates = try_compressions(data) + try_base_decodes(data)
        for label, decoded in candidates:
            h = hashlib.sha256(decoded).hexdigest()
            if h in visited:
                continue
            visited.add(h)
            out_name = f"{Path(name).stem}_{label.lower()}.bin"
            saved, why = write_output(decoded_dir, out_name, decoded, state)
            if saved:
                queue.append((os.path.basename(saved), decoded, depth + 1, f"{label} decode of {name}"))
            elif why:
                archive_notes.append(f"{out_name}: {why}.")

    # Reports are text only; no extracted file is imported or executed.
    report = os.path.join(out_dir, "report.md")
    with open(report, "w", encoding="utf-8") as f:
        f.write("# BX Unpack Analyzer — static report\n\n")
        f.write("> Safety: uploaded data was inspected as bytes only. No uploaded script or binary was executed/imported.\n\n")
        f.write("## Input\n\n")
        f.write(f"- Name: `{safe_name(os.path.basename(input_path))}`\n")
        f.write(f"- Size: {len(initial)} bytes\n")
        f.write(f"- SHA-256: `{hashlib.sha256(initial).hexdigest()}`\n\n")
        f.write("## Layers and signatures\n\n")
        for i, layer in enumerate(layers, 1):
            f.write(f"### {i}. `{layer['name']}`\n")
            f.write(f"- Depth: {layer['depth']}; source: {layer['origin']}\n")
            f.write(f"- Size: {layer['size']} bytes\n")
            f.write(f"- SHA-256: `{layer['sha256']}`\n")
            if layer["signatures"]:
                for sig in layer["signatures"]:
                    f.write(f"- Signature: {sig}\n")
            else:
                f.write("- Signature: no recognized signature\n")
            f.write("\n")
        f.write("## Overall recognized signatures\n\n")
        f.writelines(f"- {x}\n" for x in all_signatures) if all_signatures else f.write("- None recognized.\n")
        f.write("\n## Extracted printable strings (sample)\n\n")
        for s in all_strings[:MAX_STRINGS]:
            # Avoid huge report lines.
            s = s[:500].replace("`", "'")
            f.write(f"- `{s}`\n")
        f.write("\n## Notes and skipped items\n\n")
        f.writelines(f"- {x}\n" for x in archive_notes) if archive_notes else f.write("- No archive/limit warnings recorded.\n")
        f.write("\n## Limits\n\n")
        f.write(f"- Max depth: {MAX_DEPTH}\n- Max single output: {MAX_SINGLE_OUTPUT} bytes\n")
        f.write(f"- Max total extracted output: {MAX_TOTAL_OUTPUT} bytes\n- Max output files: {MAX_FILES}\n")
        f.write("- Base64/Base85 are attempted only on plausible whole-file payloads; encoded blobs embedded inside source code may not be found.\n")
        f.write("- AES or other keyed encryption is not broken. ELF analysis here is signature/strings-level only; no decompiler is invoked.\n")

    archive_path = os.path.join(out_dir, "decoded_files.zip")
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, names in os.walk(decoded_dir):
            for filename in names:
                full = os.path.join(root, filename)
                zf.write(full, arcname=os.path.relpath(full, decoded_dir))
    if os.path.getsize(archive_path) == 22:  # empty ZIP
        archive_path = None
    return {"report": report, "archive": archive_path, "layers": layers}
