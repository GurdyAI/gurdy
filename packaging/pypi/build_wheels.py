#!/usr/bin/env python3
"""Build the PyPI wheels for `gurdy` from GoReleaser's dist/ output.

    packaging/pypi/build_wheels.py 0.1.0 [--out DIR]

One package, two jobs, because §3.3 says so: "the wheel bundles the Go
governance core as a platform binary (ruff/esbuild pattern)". So `gurdy` carries
the Python SDK *and* the two Go binaries:

    pipx install gurdy   -> gurdy-proxy / gurdy-verify on PATH   (§5.8)
    pip  install gurdy   -> `import gurdy` plus the bundled core (§5.9 dev mode)

Binaries ride in `gurdy-<ver>.data/scripts/`, which pip installs into the
environment's bin/ and marks executable. That is how ruff and maturin ship a
compiled binary through a wheel, and it needs no console_scripts shim — an
entry point has to be a Python callable, and wrapping a binary in a Python
process would add interpreter startup to every proxy invocation.

**A pure-Python fallback wheel is also built**, and it is not an afterthought.
The SDK is installed into someone else's agent process and must not be the
reason that install fails. On a platform we do not ship binaries for, pip falls
back to `py3-none-any`: `import gurdy` still works, the agent still gets
provenance enrichment against a proxy running elsewhere, and only the bundled
dev-mode core is missing. That is the SDK's standing rule — degrade, never break
— applied to packaging.

No build dependencies: a wheel is a zip with three metadata files, and adding
`build`/`hatchling`/`wheel` to produce one would be more moving parts than the
format has. Output is deterministic (fixed member timestamps) so the wheels
inherit the reproducibility property of the binaries inside them.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import pathlib
import shutil
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SDK_SRC = ROOT / "sdk" / "python" / "src" / "gurdy"
DIST = ROOT / "dist"
BINARIES = ("gurdy-proxy", "gurdy-verify")

# Go's (goos, goarch) -> the PEP 425 platform tag pip matches against.
#
# The macOS minimums are the oldest release each arch can run on (arm64 did not
# exist before 11.0); the manylinux tags say "glibc >= 2.17", which a
# CGO_ENABLED=0 static Go binary satisfies trivially — it has no libc
# dependency at all, so the tag is a floor we clear rather than one we meet.
PLATFORMS = {
    ("darwin", "arm64"): "macosx_11_0_arm64",
    ("darwin", "amd64"): "macosx_10_13_x86_64",
    ("linux", "amd64"): "manylinux_2_17_x86_64.manylinux2014_x86_64",
    ("linux", "arm64"): "manylinux_2_17_aarch64.manylinux2014_aarch64",
}

# Fixed timestamp for every zip member. Without it the wheel embeds build time
# and two builds of one commit differ — the same defect the release pipeline
# avoids for the binaries (see docs/reproducible-builds.md).
ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def metadata(version: str) -> str:
    readme = (ROOT / "sdk" / "python" / "README.md").read_text(encoding="utf-8")
    return (
        "Metadata-Version: 2.1\n"
        "Name: gurdy\n"
        f"Version: {version}\n"
        "Summary: A flight recorder for AI agents — governs agent tool calls and writes a verifiable decision ledger\n"
        "Home-page: https://github.com/GurdyAI/gurdy\n"
        "License: Apache-2.0\n"
        "Requires-Python: >=3.11\n"
        "Classifier: License :: OSI Approved :: Apache Software License\n"
        "Classifier: Programming Language :: Python :: 3\n"
        "Classifier: Topic :: Security\n"
        "Classifier: Topic :: System :: Monitoring\n"
        "Provides-Extra: httpx\n"
        'Requires-Dist: httpx>=0.27; extra == "httpx"\n'
        "Description-Content-Type: text/markdown\n"
        "\n" + readme
    )


def wheel_meta(tag: str, purelib: bool) -> str:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: gurdy-build_wheels\n"
        f"Root-Is-Purelib: {'true' if purelib else 'false'}\n"
        f"Tag: {tag}\n"
    )


def _record_line(name: str, data: bytes) -> tuple[str, str, int]:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return (name, f"sha256={digest}", len(data))


def build(version: str, out: pathlib.Path, tag: str, binaries: dict[str, bytes]) -> pathlib.Path:
    """Write one wheel. `binaries` empty => the pure-Python fallback."""
    dist_info = f"gurdy-{version}.dist-info"
    data_dir = f"gurdy-{version}.data/scripts"
    members: list[tuple[str, bytes]] = []

    for path in sorted(SDK_SRC.rglob("*")):
        if path.is_file() and path.suffix in {".py", ".typed"} or path.name == "py.typed":
            members.append((f"gurdy/{path.relative_to(SDK_SRC).as_posix()}", path.read_bytes()))
    if not members:
        sys.exit(f"error: no SDK sources found under {SDK_SRC}")

    for name, blob in binaries.items():
        members.append((f"{data_dir}/{name}", blob))

    members.append((f"{dist_info}/METADATA", metadata(version).encode()))
    members.append((f"{dist_info}/WHEEL", wheel_meta(tag, purelib=not binaries).encode()))
    members.append((f"{dist_info}/LICENSE", (ROOT / "LICENSE").read_bytes()))
    members.append((f"{dist_info}/NOTICE", (ROOT / "NOTICE").read_bytes()))

    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for name, data in members:
        writer.writerow(_record_line(name, data))
    writer.writerow((f"{dist_info}/RECORD", "", ""))
    members.append((f"{dist_info}/RECORD", record.getvalue().encode()))

    out.mkdir(parents=True, exist_ok=True)
    path = out / f"gurdy-{version}-py3-none-{tag}.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            # 0o755 for the binaries so the mode survives even where pip does
            # not re-apply it; 0o644 for everything else.
            executable = name.startswith(data_dir)
            info.external_attr = ((0o755 if executable else 0o644) << 16) | (0o100000)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("version")
    ap.add_argument("--out", default=str(pathlib.Path(__file__).parent / "out"))
    args = ap.parse_args()
    version = args.version.lstrip("v")
    out = pathlib.Path(args.out)
    if out.exists():
        shutil.rmtree(out, ignore_errors=True)

    built = []
    for (goos, goarch), tag in PLATFORMS.items():
        blobs = {}
        for b in BINARIES:
            matches = sorted(DIST.glob(f"{b}_{goos}_{goarch}*/{b}"))
            if not matches:
                sys.exit(
                    f"error: no {b} for {goos}/{goarch} under {DIST}\n"
                    "run: goreleaser build --snapshot --clean"
                )
            blobs[b] = matches[0].read_bytes()
        built.append(build(version, out, tag, blobs))

    # The fallback. Last, so a failure above stops us shipping a pure wheel that
    # would otherwise be *preferred* by pip on platforms whose platform wheel
    # silently went missing — turning a build error into a dev-mode-less install
    # nobody noticed.
    built.append(build(version, out, "any", {}))

    for p in built:
        print(f"  {p.name:<58} {p.stat().st_size / 1_048_576:6.1f} MiB")
    print(f"\n{len(built)} wheels in {out}")
    print("publish with:  uvx twine upload " + str(out) + "/*.whl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
