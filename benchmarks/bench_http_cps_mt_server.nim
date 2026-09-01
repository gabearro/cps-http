## Official web-frameworks HTTP workload on `newMultiThreadRuntime`.
##
## This deliberately mirrors the-benchmarker/web-frameworks adapter so that
## runtime comparisons change the execution engine, not the HTTP workload.
## Compile against a local runtime checkout with:
##   nim c -d:danger --path:../cps-runtime/src \
##     benchmarks/bench_http_cps_mt_server.nim

import std/os
import cps/runtime
import cps/mt
import cps/http/server/dsl
import cps/http/server/server

proc startShard(shardId: int) {.gcsafe.} =
  {.cast(gcsafe).}:
    let handler = router:
      get "/":
        respond 200

      get "/user/{id}":
        respond 200, pathParams["id"]

      post "/user":
        respond 200

    let server = newHttpServer(
      handler,
      host = "0.0.0.0",
      port = 3000,
      enableHttp2 = false,
      reusePort = true,
      tcpNoDelay = true
    )
    server.bindAndListen()
    discard server.start()

proc main() =
  let runtime = newMultiThreadRuntime()
  setMainRuntime(runtime)
  setCurrentRuntime(runtime)
  runtime.startMtNetworkShards(startShard)
  while true:
    sleep(1000)

main()
