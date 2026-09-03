version = "2.0.2"
author = "Gabriel Arroyo"
description = "HTTP/1.1, HTTP/2 and HTTP/3 clients and servers for the CPS Nim runtime."
license = "MIT"
srcDir = "src"
skipDirs = @["tests", "examples", "benchmarks", ".github"]

requires "nim >= 2.0.0"
requires "https://github.com/gabearro/cps-runtime == 2.0.2"
requires "https://github.com/gabearro/cps-tls == 2.0.2"
requires "https://github.com/gabearro/cps-quic == 2.0.2"
requires "checksums >= 0.2.2"
requires "zippy >= 0.10.0"

task checkDocs, "Verify developer documentation coverage":
  exec "python3 scripts/check_dev_docs.py"

task docs, "Generate the HTML API reference":
  exec "python3 scripts/build_docs.py"

task test, "Run the project test suite":
  exec "nim c -r tests/http/test_compression.nim"
  exec "nim c -r tests/http/test_http_dsl.nim"
  exec "nim c -r tests/http/test_http_server.nim"
  exec "nim c -r tests/http/test_ws_hardening.nim"

task testMms, "Run HTTP under ARC, ORC, and AtomicARC":
  for mm in ["arc", "orc", "atomicArc"]:
    exec "nim c -r --threads:on --mm:" & mm & " tests/http/test_compression.nim"
    exec "nim c -r --threads:on --mm:" & mm & " tests/http/test_http_dsl.nim"
    exec "nim c -r --threads:on --mm:" & mm & " tests/http/test_http_server.nim"
    exec "nim c -r --threads:on --mm:" & mm & " tests/http/test_http_server_mt.nim"
    exec "nim c -r --threads:on --mm:" & mm & " tests/http/test_ws_hardening.nim"
