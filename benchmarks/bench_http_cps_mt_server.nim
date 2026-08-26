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
import cps/eventloop
import cps/io/tcp
import cps/io/streams
import cps/http/server/dsl
import cps/http/server/http1

proc startAccepting(listener: TcpListener, handler: HttpHandler) =
  let config = HttpServerConfig()
  listener.acceptEach(proc(client: TcpStream) =
    discard handleHttp1Connection(client.AsyncStream, config, handler)
  )

proc startShard(shardId: int) {.gcsafe.} =
  {.cast(gcsafe).}:
    let handler = router:
      get "/":
        respond 200

      get "/user/{id}":
        respond 200, pathParams["id"]

      post "/user":
        respond 200

    let listener = tcpListen("0.0.0.0", 3000, reusePort = true,
                             deferAcceptSeconds = 1, noDelay = true)
    startAccepting(listener, handler)

proc main() =
  let runtime = newMultiThreadRuntime()
  setMainRuntime(runtime)
  setCurrentRuntime(runtime)
  runtime.startMtIoShards(startShard)
  while true:
    sleep(1000)

main()
