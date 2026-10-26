#!/usr/bin/env python3
#
# On the Linux runner, under CodeQL's build tracing: each compile
# capture.sh wrote down on FreeBSD done again with the runner's clang,
# for FreeBSD's target (or emcc's, wasm32-unknown-emscripten) against
# the headers captured with it.  Paths in the tree go to this checkout,
# the build's obj/ directories and everything else outside the tree to
# the capture (outside the checkout, so CodeQL reports nothing in
# generated code).
#
#	replay.py <capture directory>
#
# What only matters to the real build goes: -Werror, dependency files,
# debug information, base clang's own builtin headers (the runner's
# clang has its own), emcc's -s settings.

import json
import os
import subprocess
import sys
import tempfile

SRC = "/usr/src/arcana"
cap = os.path.abspath(sys.argv[1])
ws = os.environ.get("GITHUB_WORKSPACE", os.getcwd())
root = os.path.join(cap, "root")
with open(os.path.join(cap, "emcc-sysroot")) as f:
    emsysroot = root + f.read().strip()


OBJS = ("/obj", "/cblink/obj")


def path(p):
    for o in OBJS:
        if p == SRC + o or p.startswith(SRC + o + "/"):
            return cap + p[len(SRC):]
    if p == SRC or p.startswith(SRC + "/"):
        return ws + p[len(SRC):]
    if p.startswith("/"):
        return root + p
    return p


DROP = {"-Werror", "-MD", "-MMD", "-MP", "-nobuiltininc", "-g",
        "-Qunused-arguments"}
DROP_NEXT = {"-MF", "-MT", "-MQ"}
PATH_NEXT = {"-I", "-isystem", "-iquote", "-include", "-idirafter",
             "-imacros"}


def rewrite(args, out):
    new, i = [], 0
    while i < len(args):
        a = args[i]
        i += 1
        if a in DROP or a.startswith(("-Werror=", "-g", "-s")) and \
                not a.startswith("-std"):
            continue
        if a in DROP_NEXT:
            i += 1
            continue
        if a == "-o":
            new += ["-o", out]
            i += 1
            continue
        if a == "-idirafter" and "/lib/clang/" in args[i]:
            i += 1
            continue
        if a in PATH_NEXT:
            new += [a, path(args[i])]
            i += 1
            continue
        if a.startswith("-I") and len(a) > 2:
            new.append("-I" + path(a[2:]))
            continue
        if a.startswith("/"):
            new.append(path(a))
            continue
        new.append(a)
    return new


def main():
    tmp = tempfile.mkdtemp(prefix="replay-")
    n = failed = 0
    with open(os.path.join(cap, "compiles.log")) as f:
        compiles = [json.loads(line) for line in f if line.strip()]
    for c in compiles:
        n += 1
        if c["kind"] == "emcc":
            target = ["--target=wasm32-unknown-emscripten",
                      "--sysroot=" + emsysroot,
                      "-isystem", emsysroot + "/include"]
        else:
            target = ["--target=x86_64-unknown-freebsd16",
                      "--sysroot=" + root]
        cmd = [os.environ.get("CLANG", "clang")] + target + \
            rewrite(c["args"], os.path.join(tmp, "%d.o" % n))
        cwd = path(c["cwd"])
        os.makedirs(cwd, exist_ok=True)
        r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        if r.returncode != 0:
            failed += 1
            print("replay: failed in %s: %s\n%s" % (cwd, " ".join(cmd),
                                                    r.stdout[-2000:]))
    print("replay: %d compiles, %d failed" % (n, failed))
    # A few may fail on the runner's clang; most failing is a broken
    # capture, and an analysis of nothing would pass for a clean one.
    sys.exit(1 if n == 0 or failed * 10 > n else 0)


main()
