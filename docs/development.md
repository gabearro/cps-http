# HTTP developer guide

The HTTP package shares request, response, compression, and protocol state
without forcing HTTP/1.1, HTTP/2, and HTTP/3 through one transport abstraction.
Each protocol keeps its own framing and lifecycle while the client and server
layers expose the same application model.

## Source layout

| Path | Responsibility |
| --- | --- |
| `cps/http/client/client` | High-level client, redirects, ALPN, and pooling |
| `cps/http/client/http1` | HTTP/1.1 client framing |
| `cps/http/client/http3` | HTTP/3 sessions over QUIC |
| `cps/http/server/http1` | Incremental request parser and response writer |
| `cps/http/server/http2` | HTTP/2 server connection and stream dispatch |
| `cps/http/server/dsl` | Router DSL, middleware, hooks, and generated handlers |
| `cps/http/shared/http2` | HTTP/2 frames, settings, flow control, and HPACK |
| `cps/http/shared/http3` | HTTP/3 frames, QPACK, and control streams |
| `cps/http/shared/ws` | WebSocket framing and compression |
| `cps/http/middleware` | Reusable request/response policies |

## Request flow

The transport parser produces a request with explicit framing boundaries. The
router matches method and path, populates parameters, and runs middleware and
the selected handler. The protocol writer normalizes response framing before
bytes are sent. Keep routing concerns out of wire parsers and keep protocol
state out of middleware.

## Invariants

- A parser never consumes bytes belonging to the next request or frame.
- Conflicting or ambiguous message framing is rejected.
- Header names and values are validated before they reach a wire encoder.
- HTTP/2 and HTTP/3 stream state transitions follow their protocol state
  machines; connection errors and stream errors remain distinct.
- Flow-control credit is consumed and returned exactly once.
- A pooled connection is reused only when framing and peer state allow it.
- WebSocket control frames remain bounded and are never fragmented.

## Extending the package

For a new HTTP feature, decide whether it belongs to shared semantics, one wire
protocol, or the application layer. Add protocol fixtures for malformed input,
not only a successful round trip. DSL additions must preserve generated-name
hygiene and middleware ordering.

Every exported callable needs a `##` comment. Describe framing, ownership,
stream state, middleware order, or error mapping where applicable. Generated
helpers still need a useful contract; a macro name is not its documentation.

## Validation

```sh
nimble checkDocs
nimble test
```

Run protocol interop after changing HPACK, QPACK, TLS negotiation, or QUIC
integration. Run the benchmark adapter only after correctness tests pass.
