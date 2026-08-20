version = "1.0.0"
author = "Gabriel Arroyo"
description = "HTTP/1.1, HTTP/2 and HTTP/3 clients and servers for the CPS Nim runtime."
license = "MIT"
srcDir = "src"
skipDirs = @["tests", "examples", "benchmarks", ".github"]

requires "nim >= 2.0.0"
requires "https://github.com/gabearro/cps-runtime@#v1.0.0"
requires "https://github.com/gabearro/cps-tls@#v1.0.0"
requires "https://github.com/gabearro/cps-quic@#v1.0.0"
requires "zippy >= 0.10.0"

task test, "Run the project test suite":
  exec "nim c -r tests/http/test_compression.nim"
  exec "nim c -r tests/http/test_http_dsl.nim"
  exec "nim c -r tests/http/test_http_server.nim"
  exec "nim c -r tests/http/test_ws_hardening.nim"

