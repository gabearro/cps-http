# CPS HTTP

HTTP clients and servers for the CPS runtime, with one shared implementation of
the protocol machinery used by both sides. HTTP/1.1, HTTP/2, and HTTP/3 live in
this repository because they share header handling, compression, WebSocket,
WebTransport, and connection state.

## Features

### Client

- HTTP/1.1 and HTTP/2 with ALPN negotiation
- HTTP/3 over `cps-quic`
- Connection pooling, redirects, cookies, and decompression
- HTTPS with configurable browser fingerprint profiles
- WebSocket and Server-Sent Events clients
- Streaming request and response bodies

### Server

- HTTP/1.1 and HTTP/2, plus HTTP/3 foundations
- Sinatra-style routing DSL
- Path parameters, wildcards, optional segments, and sub-routers
- Middleware, compression, sessions, rate limits, and request timeouts
- WebSocket, SSE, chunked streaming, multipart uploads, and static files
- WebTransport and MASQUE protocol support

## Requirements

- Nim 2.0 or newer
- [cps-runtime](https://github.com/gabearro/cps-runtime)
- [cps-tls](https://github.com/gabearro/cps-tls)
- [cps-quic](https://github.com/gabearro/cps-quic)
- `checksums` and `zippy` from Nimble

## Install

```sh
nimble install https://github.com/gabearro/cps-http@#v1.0.1
```

## HTTPS client

```nim
import cps
import cps/httpclient

proc main(): CpsVoidFuture {.cps.} =
  let client = newHttpsClient()

  let response = await client.get("https://httpbin.org/get")
  echo response.statusCode
  echo response.httpVersion
  echo response.body

  let posted = await client.post(
    "https://httpbin.org/post",
    "hello from CPS"
  )
  echo posted.statusCode

runCps(main())
```

The client selects HTTP/2 or HTTP/1.1 through ALPN. HTTP/3 uses the same public
response types and shared header model.

## HTTP server DSL

```nim
import cps/http/server/dsl

let handler = router:
  get "/":
    text 200, "Hello, world!"

  get "/users/{id:int}":
    json 200, $(%*{
      "id": pathParams["id"],
      "name": "Alice"
    })

  post "/echo":
    respond 200, body()

  ws "/chat":
    while true:
      let message = await recvMessage()
      await sendText("echo: " & message.data)

  sse "/events":
    for i in 0 ..< 10:
      await sendEvent($i, event = "tick")
      await cpsSleep(1000)

  serveStatic "/static", "./public"

serve(handler, port = 8080)
```

## Middleware

```nim
let handler = router:
  cors:
    origins "https://example.com"

  compress()
  maxBodySize 1_048_576
  rateLimit 100, 60
  timeout 30_000

  get "/health":
    text 200, "ok"
```

Request helpers include `body`, `jsonBody`, `formParams`, `upload`,
`bearerToken`, `basicAuth`, `clientIp`, `pathParams`, and
`queryParams`. Response helpers include `json`, `html`, `text`,
`redirect`, `sendFile`, and `download`.

## WebSocket client

```nim
import cps
import cps/http/client/ws

proc echo(): CpsVoidFuture {.cps.} =
  let socket = await wssConnect("echo.websocket.org", 443)
  await socket.sendText("hello")
  let message = await socket.recvMessage()
  echo message.data
  socket.close()

runCps(echo())
```

## TLS and HTTP/3

The default TLS path uses OpenSSL. Browser-level TLS fingerprint details and
QUIC handshakes use BoringSSL:

```sh
bash scripts/build_boringssl.sh
nim c -r -d:useBoringSSL your_program.nim
```

## Imports

| Import | Functionality |
| --- | --- |
| `cps/httpclient` | Client, pooling, HTTPS, redirects |
| `cps/httpserver` | Server and router types |
| `cps/http/server/dsl` | Declarative server DSL |
| `cps/http/client/ws` | WebSocket client |
| `cps/http/client/sse` | SSE client |
| `cps/http/shared/http2` | HTTP/2 codec/state |
| `cps/http/shared/http3` | HTTP/3 codec/state |

## Development

Read the [HTTP developer guide](docs/development.md) before changing public
APIs, ownership, protocol state, or execution behavior.

```sh
nimble install -d -y
nimble checkDocs
nimble docs
nimble test
```

`nimble docs` writes the generated API reference to
[`docs/api/theindex.html`](docs/api/theindex.html).

The suite covers compression, the DSL, HTTP/1.1 and HTTP/2 server behavior,
TLS, and WebSocket hardening. Protocol-specific interop tests remain
standalone so they can bring their own Python or browser dependencies.

## License

MIT
