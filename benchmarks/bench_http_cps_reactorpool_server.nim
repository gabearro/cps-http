## Official web-frameworks HTTP workload on the sharded reactor pool.
##
## Each shard owns its runtime, selector, futures, and HTTP state, so this
## server is intentionally compiled with regular ``--mm:arc``. GC-managed
## values must not cross reactor threads.
##
## Build locally with ``Dockerfile.mt-local`` using:
##   --build-arg BENCH_SERVER=benchmarks/bench_http_cps_reactorpool_server.nim
##   --build-arg NIM_MM=arc

import cps/runtime
import cps/reactorpool
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

runReactorPool(startShard)
