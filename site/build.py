#!/usr/bin/env python3
"""Prepare site/ for publishing and check its numbers. Python standard library and Go.

    python3 -I site/build.py

1. Builds saltlick, starts it on a free local port with an empty database, and
   runs one session against it: a publish refused for carrying offers, a pointer
   record and its package published with the published conformance test key, an
   overwrite attempted with a second key, and the reads a counterparty makes.
   Every request and response is written to site/assets/from-tree/session.json
   (git-ignored). The hero replays that file; the visitor's browser recomputes
   the package digest and, where it can, verifies the package signature.
2. Copies the README figure beside it.
3. Measures the numbers on the page and fails if site/index.html states
   anything else.

The session runs against http://127.0.0.1:<port>; the page shows the host as
directory.example, the name the README uses.
"""

import base64
import glob
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
OUT = os.path.join(SITE, "assets", "from-tree")
HOST = "directory.example"

PACKAGE = {
    "spec": "federation-package/v1",
    "sovereign_id": "xaa",
    "issued": "2026-09-06",
    "expires": "2026-12-06",
    "identity": {
        "trust_domain": "spiffe://xaa.example",
        "ca_fingerprint": "sha256:d49211cac3357142f3cf9c2ee216cdd452793ce89428d5ea856f9f62e71efe55",
    },
    "capabilities": {
        "transports": ["ipsec-fips", "wireguard"],
        "fabric_fips_image": True,
        "pqc_capable": True,
        "fabric_version": "1.9.0",
    },
}


def run(*args, cwd):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


def sign(binary, work, key, *args):
    """Run saltlick sign; return the X-Saltlick-* headers it prints (stderr when signing a package, else stdout)."""
    out = run(binary, "sign", "-key", key, *args, cwd=work)
    return dict(re.findall(r"^(X-Saltlick-[A-Za-z]+): (\S+)$", out.stderr + "\n" + out.stdout, re.M))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def exchange(base, method, path, body=None, headers=None):
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def session(binary, work):
    # The published conformance-vector test key (internal/pkgv1/testdata/README.md): worthless on purpose.
    with open(os.path.join(ROOT, "internal/pkgv1/testdata/xaa.seed.hex")) as f:
        seed = bytes.fromhex(f.read().strip())
    with open(os.path.join(work, "xaa.key"), "w") as f:
        f.write(base64.b64encode(seed).decode() + "\n")
    # A second, fixed key standing for someone else trying to take the entry over.
    with open(os.path.join(work, "other.key"), "w") as f:
        f.write(base64.b64encode(hashlib.sha256(b"saltlick landing page: another key").digest()).decode() + "\n")

    with open(os.path.join(work, "xaa.json"), "w") as f:
        json.dump(PACKAGE, f, indent=2)
    pkg_headers = sign(binary, work, "xaa.key", "-package", "xaa.json", "-out", "xaa.signed.json")
    with open(os.path.join(work, "xaa.signed.json"), "rb") as f:
        package = f.read()
    digest = "sha256:" + hashlib.sha256(package).hexdigest()
    pointer = {
        "spec": "saltlick-pointer/v1",
        "sovereign_id": "xaa",
        "package_url": f"https://{HOST}/v1/parties/xaa/package",
        "package_sha256": digest,
        "expires": "2026-12-06",
    }
    with open(os.path.join(work, "xaa.pointer.json"), "w") as f:
        json.dump(pointer, f, indent=2)
    ptr_headers = sign(binary, work, "xaa.key", "-package", "xaa.pointer.json", "-out", "xaa.pointer.signed.json")
    with open(os.path.join(work, "xaa.pointer.signed.json"), "rb") as f:
        pointer_bytes = f.read()
    other_headers = sign(binary, work, "other.key", "-package", "xaa.pointer.json", "-out", "other.pointer.json")
    with open(os.path.join(work, "other.pointer.json"), "rb") as f:
        other_bytes = f.read()
    upload_headers = sign(binary, work, "xaa.key", "-upload", "package", "-file", "xaa.signed.json", "-id", "xaa")
    with open(os.path.join(ROOT, "internal/pkgv1/testdata/full-offer-xaa.json"), "rb") as f:
        full_offer = f.read()

    port = free_port()
    server = subprocess.Popen(  # noqa: S603 - the binary this script just built
        [binary, "serve", "-addr", f"127.0.0.1:{port}", "-db", os.path.join(work, "saltlick.db")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if exchange(base, "GET", "/healthz")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        steps = []

        def step(who, title, method, path, body=None, headers=None, sent=None):
            status, hdrs, text = exchange(base, method, path, body, headers)
            steps.append(
                {
                    "who": who,
                    "title": title,
                    "method": method,
                    "path": path,
                    "sent": sent,
                    "status": status,
                    "advisory": hdrs.get("X-Saltlick-Advisory"),
                    "body": text,
                }
            )
            return status, text

        # The offer refusal comes before any signature check, so this request's signature is not examined.
        step(
            "party",
            "publish a package that carries offers",
            "PUT",
            "/v1/parties/xaa",
            full_offer,
            {"X-Saltlick-Key": ptr_headers["X-Saltlick-Key"], "X-Saltlick-Signature": "A" * 86 + "=="},
            "internal/pkgv1/testdata/full-offer-xaa.json",
        )
        step("party", "publish the pointer record", "PUT", "/v1/parties/xaa", pointer_bytes, ptr_headers, "xaa.pointer.signed.json")
        step("party", "host the package beside it", "PUT", "/v1/parties/xaa/package", package, upload_headers, "xaa.signed.json")
        step("other", "another key tries to take the entry", "PUT", "/v1/parties/xaa", other_bytes, other_headers, "a pointer signed by another key")
        status, listed = step("reader", "read the pointer", "GET", "/v1/parties/xaa")
        _, served = step("reader", "fetch the package it names", "GET", "/v1/parties/xaa/package")
        version = json.loads(exchange(base, "GET", "/v1/version")[2])
    finally:
        server.terminate()
        server.wait(timeout=10)

    expect = [422, 201, 201, 403, 200, 200]
    got = [s["status"] for s in steps]
    if got != expect:
        sys.exit(f"site/build.py: the session answered {got}, the page is written for {expect}")
    if listed.encode() != pointer_bytes or served.encode() != package:
        sys.exit("site/build.py: the directory did not serve the bytes it was given")
    return {
        "host": HOST,
        "key_read_aloud": pkg_headers["X-Saltlick-Key"],
        "steps": steps,
        "routes": len(version["routes"]),
    }


def measure(routes):
    with open(os.path.join(ROOT, "internal/httpapi/server.go")) as f:
        cap = re.search(r"const MaxBodyBytes = (\d+) << 10", f.read())
    with open(os.path.join(ROOT, "internal/pkgv1/package.go")) as f:
        offers = re.search(r"var offerMembers = map\[string\]string\{(.*?)\n\}", f.read(), re.S)
    tests = 0
    for path in glob.glob(os.path.join(ROOT, "**/*_test.go"), recursive=True):
        with open(path) as f:
            tests += len(re.findall(r"^func Test", f.read(), re.M))
    return {
        "routes": str(routes),
        "cap": f"{cap.group(1)} KiB",
        "offers": str(len(re.findall(r'^\s*"[a-z_]+":', offers.group(1), re.M))),
        "tests": str(tests),
    }


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in ("peering-directory-light.svg", "peering-directory-dark.svg"):
        shutil.copyfile(os.path.join(ROOT, "docs/figures", name), os.path.join(OUT, name))
    with tempfile.TemporaryDirectory() as work:
        binary = os.path.join(work, "saltlick")
        run("go", "build", "-o", binary, "./cmd/saltlick", cwd=ROOT)
        data = session(binary, work)
    with open(os.path.join(OUT, "session.json"), "w") as f:
        json.dump(data, f, indent=1)

    with open(os.path.join(SITE, "index.html")) as f:
        page = f.read()
    measured = measure(data["routes"])
    stated = dict(re.findall(r'data-measure="([a-z0-9-]+)">([^<]*)<', page))
    bad = 0
    for key, value in measured.items():
        if stated.get(key) != value:
            print(f"site/index.html: {key} says {stated.get(key)}, the tree gives {value}")
            bad += 1
    for key in stated.keys() - measured.keys():
        print(f'site/index.html: data-measure="{key}" is not measured by site/build.py')
        bad += 1
    if bad:
        return 1
    print("site: numbers match the tree:", ", ".join(f"{k}={v}" for k, v in measured.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
