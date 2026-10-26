#!/usr/local/bin/python3
#
# The compiler, cc(1) or emcc(1), with each compile written down for
# CodeQL: where it ran and its arguments, one JSON line each in
# $CODEQL_LOG.  Run as cc or emcc (capture.sh links both names here);
# the real one is $CODEQL_CC or $CODEQL_EMCC.

import json
import os
import sys

kind = "emcc" if os.path.basename(sys.argv[0]) == "emcc" else "cc"
real = os.environ["CODEQL_EMCC" if kind == "emcc" else "CODEQL_CC"]
args = sys.argv[1:]
if "-c" in args:
    with open(os.environ["CODEQL_LOG"], "a") as f:
        f.write(json.dumps({"kind": kind, "cwd": os.getcwd(),
                            "args": args}) + "\n")
os.execvp(real, [real] + args)
