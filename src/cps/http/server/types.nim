## HTTP Server Types
##
## Core types for the HTTP server: HttpRequest, HttpResponseBuilder,
## HttpHandler, HttpServerConfig, HttpServer.

import std/[strutils, nativesockets, tables, json, hashes]
import cps/private/platform
import cps/runtime
import cps/eventloop
import cps/concurrency/taskgroup
import cps/io/tcp
import cps/io/streams
import cps/io/buffered

type
  ByteView* = object
    ## Ephemeral, non-owning view over request bytes. The view is valid only
    ## while the request handler is running. Call `toString` to retain it.
    data*: ptr UncheckedArray[char]
    len*: int

  HttpHeaderView* = tuple[name: ByteView, value: ByteView]

  HttpHeadersStorage = enum
    hhsRawHttp1, hhsPairs

  HttpHeadersView* = object
    ## Allocation-free request-header view. HTTP/1 headers are scanned from
    ## the wire buffer; HTTP/2 and HTTP/3 share their decoder-owned field list.
    case storage: HttpHeadersStorage
    of hhsRawHttp1:
      raw: ByteView
      rawCount: int
    of hhsPairs:
      pairsData: ptr UncheckedArray[(string, string)]
      pairsLen: int
      pairCount: int

  RequestOwnedStorage = ref object
    methodValue: string
    pathValue: string
    versionValue: string
    authorityValue: string
    schemeValue: string
    body: string
    headers: seq[(string, string)]

  ResponseControl* = enum
    rcNone,          ## Normal HTTP response
    rcPassRoute,     ## Internal router control: continue to next matching route
    rcContinue,      ## Internal middleware control: continue chain
    rcHandled        ## Response already written directly to transport

  TemplateRenderer* = proc(name: string, vars: JsonNode): string {.closure.}

  HttpRequest* = object
    ## Parsed request data is borrowed. It must not escape the handler unless
    ## explicitly copied with `toString`/`toSeq`.
    meth*: ByteView
    path*: ByteView
    httpVersion*: ByteView
    headers*: HttpHeadersView
    body*: ByteView
    remoteAddr*: string     ## Remote peer IP address.
    streamId*: uint32       ## HTTP/2 stream ID (0 for HTTP/1.1)
    authority*: ByteView    ## HTTP/2 :authority pseudo-header
    scheme*: ByteView       ## HTTP/2 :scheme pseudo-header
    stream*: AsyncStream    ## Underlying transport (for SSE/WebSocket). nil for HTTP/2.
    reader*: BufferedReader  ## HTTP/1.1 buffered reader (for WebSocket). nil for HTTP/2.
    templateRenderer*: TemplateRenderer  ## Router-scoped template renderer (if configured).
    context*: TableRef[string, string]  ## Shared per-request context across request copies
    appState*: RootRef      ## Typed app state injected by router dispatch
    maxWsFrameBytes*: int   ## Per-request WebSocket frame limit inherited from the server.
    maxWsMessageBytes*: int ## Per-request WebSocket message limit inherited from the server.

    ownedStorage: RequestOwnedStorage

  HttpResponseBuilder* = object
    statusCode*: int
    headers*: seq[(string, string)]
    body*: ByteView
    control*: ResponseControl
    bodyStorage: string

  HttpHandler* = proc(req: HttpRequest): CpsFuture[HttpResponseBuilder] {.closure.}

  HttpServerConfig* = object
    host*: string
    port*: int
    certFile*: string
    keyFile*: string
    useTls*: bool
    enableHttp2*: bool
    enableHttp3*: bool
    quicIdleTimeoutMs*: int
    quicUseRetry*: bool
    quicEnableMigration*: bool
    quicEnableDatagram*: bool
    quicMaxDatagramFrameSize*: int
    quicInitialMaxData*: uint64
    quicInitialMaxStreamDataBidiLocal*: uint64
    quicInitialMaxStreamDataBidiRemote*: uint64
    quicInitialMaxStreamDataUni*: uint64
    quicInitialMaxStreamsBidi*: uint64
    quicInitialMaxStreamsUni*: uint64
    maxConnections*: int
    reusePort*: bool
    deferAcceptSeconds*: int
    tcpNoDelay*: bool
    initialReadBufferBytes*: int
    maxRequestBodySize*: int
    readTimeoutMs*: int
    maxRequestLineSize*: int
    maxHeaderLineSize*: int
    maxHeaderBytes*: int
    maxHeaderCount*: int
    maxWsFrameBytes*: int
    maxWsMessageBytes*: int
    trustedProxyCidrs*: seq[string]
    trustedForwardedHeaders*: bool

  HttpServer* = ref object
    config*: HttpServerConfig
    listener*: TcpListener
    handler*: HttpHandler
    running*: bool
    boundPort*: int
    connGroup*: TaskGroup
    acceptStopSignal*: CpsVoidFuture
    shutdownStarted*: bool
    onStartCallbacks*: seq[proc()]
    onShutdownCallbacks*: seq[proc()]

proc view*(s: openArray[char]): ByteView {.inline.} =
  ## Borrow a string's storage. The caller must keep `s` alive and unchanged.
  if s.len > 0:
    result = ByteView(data: cast[ptr UncheckedArray[char]](unsafeAddr s[0]), len: s.len)

proc view*(bytes: openArray[byte]): ByteView {.inline.} =
  ## Borrow a byte sequence's storage. The caller must keep it alive unchanged.
  if bytes.len > 0:
    result = ByteView(
      data: cast[ptr UncheckedArray[char]](unsafeAddr bytes[0]),
      len: bytes.len)

proc view*(data: ptr UncheckedArray[char], len: int): ByteView {.inline.} =
  ## Borrow `len` characters beginning at `data`.
  if len > 0:
    result = ByteView(data: data, len: len)

proc view*(data: ptr UncheckedArray[char], start, len: int): ByteView {.inline.} =
  ## Borrow a subrange of pointer-backed character storage.
  if len > 0:
    result = ByteView(
      data: cast[ptr UncheckedArray[char]](addr data[start]),
      len: len
    )

proc toString*(v: ByteView): string =
  ## Materialize request bytes for storage beyond the handler lifetime.
  result = newString(v.len)
  if v.len > 0:
    copyMem(addr result[0], v.data, v.len)

proc `$`*(v: ByteView): string =
  ## Materialize a borrowed view as an owned string.
  v.toString()

proc `%`*(v: ByteView): JsonNode =
  ## Materialize only when an owning JSON string node is requested.
  %(v.toString())

proc `&`*(a: ByteView, b: string): string =
  ## Concatenate a borrowed view and owned string into new storage.
  result = newStringOfCap(a.len + b.len)
  for i in 0 ..< a.len: result.add a.data[i]
  result.add b

proc `&`*(a: string, b: ByteView): string =
  ## Concatenate an owned string and borrowed view into new storage.
  result = newStringOfCap(a.len + b.len)
  result.add a
  for i in 0 ..< b.len: result.add b.data[i]

proc setMethod*(req: var HttpRequest, value: sink string) {.inline.} =
  ## Replace the borrowed method with request-owned storage.
  if req.ownedStorage.isNil: req.ownedStorage = RequestOwnedStorage()
  req.ownedStorage.methodValue = value
  req.meth = view(req.ownedStorage.methodValue)

proc setBodyStorage*(req: var HttpRequest, value: sink string) {.inline.} =
  ## Retain an owned decoder body while exposing it through a byte view.
  if req.ownedStorage.isNil: req.ownedStorage = RequestOwnedStorage()
  req.ownedStorage.body = value
  req.body = view(req.ownedStorage.body)

## Borrow a decoder-owned header field sequence.
proc sharedHeaders*(pairs: openArray[(string, string)]): HttpHeadersView {.inline.}

proc newOwnedRequest*(meth, path: string,
                      headers: seq[(string, string)] = @[],
                      body: string = "",
                      httpVersion: string = "HTTP/1.1",
                      authority: string = "",
                      scheme: string = ""): HttpRequest =
  ## Construct a request whose byte views remain valid for the request value's
  ## lifetime. Network servers use borrowed transport storage instead.
  let storage = RequestOwnedStorage(
    methodValue: meth,
    pathValue: path,
    versionValue: httpVersion,
    authorityValue: authority,
    schemeValue: scheme,
    body: body,
    headers: headers
  )
  result.meth = view(storage.methodValue)
  result.path = view(storage.pathValue)
  result.httpVersion = view(storage.versionValue)
  result.authority = view(storage.authorityValue)
  result.scheme = view(storage.schemeValue)
  result.body = view(storage.body)
  result.headers = sharedHeaders(storage.headers)
  result.ownedStorage = storage

proc `[]`*(v: ByteView, i: int): char {.inline.} =
  ## Return the character at `i` without bounds or ownership conversion.
  v.data[i]

proc `[]`*(v: ByteView, i: BackwardsIndex): char {.inline.} =
  ## Return a character indexed from the end of the borrowed view.
  v.data[v.len - int(i)]

proc `[]`*(v: ByteView, slice: HSlice[int, int]): ByteView {.inline.} =
  ## Borrow an inclusive forward-indexed slice.
  let first = max(0, slice.a)
  let last = min(v.len - 1, slice.b)
  if first <= last:
    result = view(v.data, first, last - first + 1)

proc `[]`*(v: ByteView,
           slice: HSlice[int, BackwardsIndex]): ByteView {.inline.} =
  ## Borrow a slice whose upper bound is indexed from the end.
  let first = max(0, slice.a)
  let last = v.len - int(slice.b)
  if first <= last:
    result = view(v.data, first, last - first + 1)

iterator items*(v: ByteView): char =
  ## Iterate characters in a borrowed view without materializing a string.
  for i in 0 ..< v.len:
    yield v.data[i]

iterator pairs*(v: ByteView): (int, char) =
  ## Iterate borrowed characters together with their zero-based indexes.
  for i in 0 ..< v.len:
    yield (i, v.data[i])

proc `==`*(a, b: ByteView): bool {.inline.} =
  ## Compare two byte views without allocating.
  if a.len != b.len: return false
  for i in 0 ..< a.len:
    if a.data[i] != b.data[i]: return false
  true

proc `==`*(a: ByteView, b: string): bool {.inline.} =
  ## Compare a byte view with a string without materializing the view.
  if a.len != b.len: return false
  for i in 0 ..< a.len:
    if a.data[i] != b[i]: return false
  true

proc `==`*(a: string, b: ByteView): bool {.inline.} =
  ## Compare a string with a byte view without materializing the view.
  b == a
proc `!=`*(a: ByteView, b: string): bool {.inline.} =
  ## Return whether a byte view differs from a string.
  not (a == b)
proc `!=`*(a: string, b: ByteView): bool {.inline.} =
  ## Return whether a string differs from a byte view.
  not (b == a)

proc cmpIgnoreCase*(a: ByteView, b: string): int {.inline.} =
  ## Compare borrowed bytes with a string using ASCII case folding.
  let common = min(a.len, b.len)
  for i in 0 ..< common:
    let ac = toLowerAscii(a.data[i])
    let bc = toLowerAscii(b[i])
    if ac < bc: return -1
    if ac > bc: return 1
  cmp(a.len, b.len)

proc eqCaseInsensitive*(a: ByteView, b: string): bool {.inline.} =
  ## Test borrowed bytes and a string for ASCII case-insensitive equality.
  a.cmpIgnoreCase(b) == 0

proc eqCaseInsensitive*(a, b: ByteView): bool {.inline.} =
  ## Test two borrowed views for ASCII case-insensitive equality.
  if a.len != b.len: return false
  for i in 0 ..< a.len:
    if toLowerAscii(a.data[i]) != toLowerAscii(b.data[i]): return false
  true

proc startsWith*(v: ByteView, prefix: string): bool {.inline.} =
  ## Test whether a borrowed view starts with `prefix`.
  if prefix.len > v.len: return false
  for i in 0 ..< prefix.len:
    if v.data[i] != prefix[i]: return false
  true

proc find*(v: ByteView, needle: char, start = 0): int {.inline.} =
  ## Find a character without materializing the borrowed view.
  for i in max(0, start) ..< v.len:
    if v.data[i] == needle: return i
  -1

proc find*(v: ByteView, needle: string, start = 0): int =
  ## Find a string without materializing the borrowed view.
  if needle.len == 0: return min(max(0, start), v.len)
  if needle.len > v.len: return -1
  var i = max(0, start)
  while i <= v.len - needle.len:
    var matched = true
    for j in 0 ..< needle.len:
      if v.data[i + j] != needle[j]:
        matched = false
        break
    if matched: return i
    inc i
  -1

proc contains*(v: ByteView, needle: string): bool {.inline.} =
  ## Return whether a borrowed view contains `needle`.
  v.find(needle) >= 0

proc hash*(v: ByteView): Hash =
  ## Hash borrowed bytes using the same character-wise combination semantics.
  var h: Hash = 0
  for i in 0 ..< v.len:
    h = h !& hash(v.data[i])
  !$h

proc rawHttp1Headers*(raw: ByteView, count: int): HttpHeadersView {.inline.} =
  ## Construct a header view over an HTTP/1 wire block.
  HttpHeadersView(storage: hhsRawHttp1, raw: raw, rawCount: count)

proc sharedHeaders*(pairs: openArray[(string, string)]): HttpHeadersView {.inline.} =
  ## Construct a view over decoder-owned HTTP/2 or HTTP/3 header pairs.
  var visible = 0
  for (name, _) in pairs:
    if name.len == 0 or name[0] != ':' or name == ":protocol":
      inc visible
  HttpHeadersView(
    storage: hhsPairs,
    pairsData: (if pairs.len > 0:
      cast[ptr UncheckedArray[(string, string)]](unsafeAddr pairs[0])
    else: nil),
    pairsLen: pairs.len,
    pairCount: visible)

proc len*(headers: HttpHeadersView): int {.inline.} =
  ## Return the number of visible, non-pseudo header fields.
  case headers.storage
  of hhsRawHttp1: headers.rawCount
  of hhsPairs: headers.pairCount

iterator items*(headers: HttpHeadersView): HttpHeaderView =
  ## Iterate visible headers as borrowed name/value views.
  case headers.storage
  of hhsRawHttp1:
    var pos = 0
    while pos < headers.raw.len:
      var lineEnd = pos
      while lineEnd + 1 < headers.raw.len and
          not (headers.raw[lineEnd] == '\r' and headers.raw[lineEnd + 1] == '\n'):
        inc lineEnd
      if lineEnd + 1 >= headers.raw.len:
        lineEnd = headers.raw.len
      var colon = pos
      while colon < lineEnd and headers.raw[colon] != ':': inc colon
      if colon < lineEnd:
        var valueStart = colon + 1
        while valueStart < lineEnd and headers.raw[valueStart] in {' ', '\t'}:
          inc valueStart
        var valueEnd = lineEnd
        while valueEnd > valueStart and headers.raw[valueEnd - 1] in {' ', '\t'}:
          dec valueEnd
        yield (
          headers.raw[pos .. colon - 1],
          headers.raw[valueStart .. valueEnd - 1]
        )
      pos = lineEnd + 2
  of hhsPairs:
    for i in 0 ..< headers.pairsLen:
      let name {.cursor.} = headers.pairsData[i][0]
      let value {.cursor.} = headers.pairsData[i][1]
      if name.len == 0 or name[0] != ':' or name == ":protocol":
        yield (view(name), view(value))

proc `[]`*(headers: HttpHeadersView, index: int): HttpHeaderView =
  ## Return the visible header at `index` as borrowed views.
  var i = 0
  for header in headers:
    if i == index: return header
    inc i
  raise newException(IndexDefect, "header index out of bounds")

proc newResponse*(statusCode: int, body: string = "",
                  headers: seq[(string, string)] = @[]): HttpResponseBuilder =
  ## Create a new response.
  result = HttpResponseBuilder(
    statusCode: statusCode,
    headers: headers,
    bodyStorage: body,
    control: rcNone
  )
  result.body = view(result.bodyStorage)

proc newResponse*(statusCode: int, body: ByteView,
                  headers: seq[(string, string)] = @[]): HttpResponseBuilder =
  ## Create a response that borrows its body through write completion.
  HttpResponseBuilder(
    statusCode: statusCode,
    headers: headers,
    body: body,
    control: rcNone)

proc setBody*(resp: var HttpResponseBuilder, body: sink string) {.inline.} =
  ## Replace a response body with owned storage and refresh its view.
  resp.bodyStorage = body
  resp.body = view(resp.bodyStorage)

proc clearBody*(resp: var HttpResponseBuilder) {.inline.} =
  ## Remove response body storage and reset its borrowed view.
  resp.bodyStorage.setLen(0)
  resp.body = ByteView()

proc passRouteResponse*(headers: seq[(string, string)] = @[]): HttpResponseBuilder =
  ## Internal control response used by router `pass()`.
  HttpResponseBuilder(
    statusCode: 204,
    headers: headers,
    body: ByteView(),
    control: rcPassRoute
  )

proc continueResponse*(): HttpResponseBuilder =
  ## Internal control response used by `before` middleware to continue.
  HttpResponseBuilder(
    statusCode: 204,
    headers: @[],
    body: ByteView(),
    control: rcContinue
  )

proc handledResponse*(): HttpResponseBuilder =
  ## Internal control response used by SSE/WebSocket/chunked handlers.
  HttpResponseBuilder(
    statusCode: 200,
    headers: @[],
    body: ByteView(),
    control: rcHandled
  )

proc eqCaseInsensitive*(a, b: string): bool {.inline.} =
  ## Zero-allocation case-insensitive string comparison.
  if a.len != b.len: return false
  for i in 0 ..< a.len:
    if toLowerAscii(a[i]) != toLowerAscii(b[i]): return false
  true

proc ensureContext*(req: var HttpRequest) {.inline.} =
  ## Lazily allocate the context table on first use.
  if req.context.isNil:
    req.context = newTable[string, string]()

proc getHeader*(req: HttpRequest, name: string): ByteView =
  ## Return a request header by case-insensitive name.
  if not req.ownedStorage.isNil:
    # Re-derive the pointer from the retained owner. This also keeps manually
    # constructed requests sound when ARC chooses to copy an aggregate while
    # passing it through a closure.
    for i in 0 ..< req.ownedStorage.headers.len:
      if eqCaseInsensitive(req.ownedStorage.headers[i][0], name):
        return view(req.ownedStorage.headers[i][1])
    return ByteView()
  for (k, v) in req.headers:
    if eqCaseInsensitive(k, name):
      return v
  return ByteView()

proc getResponseHeader*(resp: HttpResponseBuilder, name: string): string =
  ## Return a response header by case-insensitive name.
  for (k, v) in resp.headers:
    if eqCaseInsensitive(k, name):
      return v
  return ""

const headerTokenChars = {'!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^',
                          '_', '`', '|', '~'} + Digits + Letters

proc isValidHeaderName*(name: string): bool =
  ## RFC token validation for header names.
  if name.len == 0:
    return false
  for c in name:
    if c notin headerTokenChars:
      return false
  true

proc isValidHeaderName*(name: ByteView): bool =
  ## Validate a borrowed header name as an RFC token.
  if name.len == 0: return false
  for c in name:
    if c notin headerTokenChars: return false
  true

proc isValidLowercaseHeaderName*(name: string): bool =
  ## Validate the lowercase token form required on HTTP/2 and HTTP/3 wires.
  if name.len == 0:
    return false
  for c in name:
    if c notin headerTokenChars or c in {'A' .. 'Z'}:
      return false
  true

proc isValidHeaderValue*(value: string): bool =
  ## Strict header value validation: rejects CR/LF and control chars (except HTAB).
  for c in value:
    if c == '\r' or c == '\n':
      return false
    if c == '\0':
      return false
    if ord(c) < 0x20 and c != '\t':
      return false
    if ord(c) == 0x7F:
      return false
  true

proc isValidHeaderValue*(value: ByteView): bool =
  ## Validate borrowed header bytes without materializing a string.
  for c in value:
    if c == '\r' or c == '\n' or c == '\0': return false
    if ord(c) < 0x20 and c != '\t': return false
    if ord(c) == 0x7F: return false
  true

proc validateHeaderPair*(name, value: ByteView): bool =
  ## Validate a borrowed header name/value pair.
  isValidHeaderName(name) and isValidHeaderValue(value)

proc validateHeaderPair*(name, value: string): bool =
  ## Validate header pair and reject malformed state.
  isValidHeaderName(name) and isValidHeaderValue(value)

proc validateResponseHeaders*(headers: seq[(string, string)]): bool =
  ## Validate response headers and reject malformed state.
  for (k, v) in headers:
    if not validateHeaderPair(k, v):
      return false
  true

proc parseIpv4(ip: string, value: var uint32): bool =
  let parts = ip.split('.')
  if parts.len != 4:
    return false
  var parsed: uint32 = 0
  for part in parts:
    if part.len == 0:
      return false
    var n = -1
    try:
      n = parseInt(part)
    except ValueError:
      return false
    if n < 0 or n > 255:
      return false
    parsed = (parsed shl 8) or uint32(n)
  value = parsed
  true

proc ipInCidr(ip: string, cidr: string): bool =
  if cidr == "*":
    return true
  let slash = cidr.find('/')
  if slash < 0:
    return ip == cidr

  let networkIp = cidr[0 ..< slash]
  let maskStr = cidr[slash + 1 .. ^1]
  var maskBits = -1
  try:
    maskBits = parseInt(maskStr)
  except ValueError:
    return false
  if maskBits < 0 or maskBits > 32:
    return false

  var ipVal, netVal: uint32
  if not parseIpv4(ip, ipVal):
    return false
  if not parseIpv4(networkIp, netVal):
    return false

  let mask: uint32 =
    if maskBits == 0: 0'u32
    else: 0xFFFF_FFFF'u32 shl (32 - maskBits)
  (ipVal and mask) == (netVal and mask)

proc isTrustedProxyAddress*(ip: string, cidrs: seq[string]): bool =
  ## Returns true when the remote peer is trusted to provide forwarded headers.
  if ip.len == 0:
    return false
  if cidrs.len == 0:
    return false
  for cidr in cidrs:
    if ipInCidr(ip, cidr.strip()):
      return true
  false

proc statusMessage*(code: int): string =
  ## Build the status message wire value.
  case code
  of 200: "OK"
  of 201: "Created"
  of 204: "No Content"
  of 205: "Reset Content"
  of 301: "Moved Permanently"
  of 302: "Found"
  of 304: "Not Modified"
  of 400: "Bad Request"
  of 403: "Forbidden"
  of 404: "Not Found"
  of 405: "Method Not Allowed"
  of 406: "Not Acceptable"
  of 408: "Request Timeout"
  of 409: "Conflict"
  of 414: "URI Too Long"
  of 411: "Length Required"
  of 413: "Payload Too Large"
  of 415: "Unsupported Media Type"
  of 417: "Expectation Failed"
  of 431: "Request Header Fields Too Large"
  of 429: "Too Many Requests"
  of 500: "Internal Server Error"
  of 502: "Bad Gateway"
  of 503: "Service Unavailable"
  of 505: "HTTP Version Not Supported"
  else: "Unknown"

proc newHttpServer*(handler: HttpHandler,
                    host: string = "127.0.0.1",
                    port: int = 0,
                    useTls: bool = false,
                    certFile: string = "",
                    keyFile: string = "",
                    enableHttp2: bool = true,
                    enableHttp3: bool = false,
                    quicIdleTimeoutMs: int = 30_000,
                    quicUseRetry: bool = true,
                    quicEnableMigration: bool = true,
                    quicEnableDatagram: bool = true,
                    quicMaxDatagramFrameSize: int = 1200,
                    quicInitialMaxData: uint64 = 1_048_576'u64,
                    quicInitialMaxStreamDataBidiLocal: uint64 = 262_144'u64,
                    quicInitialMaxStreamDataBidiRemote: uint64 = 262_144'u64,
                    quicInitialMaxStreamDataUni: uint64 = 262_144'u64,
                    quicInitialMaxStreamsBidi: uint64 = 100'u64,
                    quicInitialMaxStreamsUni: uint64 = 100'u64,
                    maxConnections: int = 1000,
                    reusePort: bool = false,
                    deferAcceptSeconds: int = 1,
                    tcpNoDelay: bool = true,
                    initialReadBufferBytes: int = 2048,
                    maxRequestBodySize: int = 10 * 1024 * 1024,
                    readTimeoutMs: int = 30000,
                    maxRequestLineSize: int = 8 * 1024,
                    maxHeaderLineSize: int = 8 * 1024,
                    maxHeaderBytes: int = 64 * 1024,
                    maxHeaderCount: int = 100,
                    maxWsFrameBytes: int = 1024 * 1024,
                    maxWsMessageBytes: int = 16 * 1024 * 1024,
                    trustedProxyCidrs: seq[string] = @[],
                    trustedForwardedHeaders: bool = false): HttpServer =
  ## Create a new HTTP server.
  let config = HttpServerConfig(
    host: host,
    port: port,
    certFile: certFile,
    keyFile: keyFile,
    useTls: useTls,
    enableHttp2: enableHttp2,
    enableHttp3: enableHttp3,
    quicIdleTimeoutMs: quicIdleTimeoutMs,
    quicUseRetry: quicUseRetry,
    quicEnableMigration: quicEnableMigration,
    quicEnableDatagram: quicEnableDatagram,
    quicMaxDatagramFrameSize: quicMaxDatagramFrameSize,
    quicInitialMaxData: quicInitialMaxData,
    quicInitialMaxStreamDataBidiLocal: quicInitialMaxStreamDataBidiLocal,
    quicInitialMaxStreamDataBidiRemote: quicInitialMaxStreamDataBidiRemote,
    quicInitialMaxStreamDataUni: quicInitialMaxStreamDataUni,
    quicInitialMaxStreamsBidi: quicInitialMaxStreamsBidi,
    quicInitialMaxStreamsUni: quicInitialMaxStreamsUni,
    maxConnections: maxConnections,
    reusePort: reusePort,
    deferAcceptSeconds: deferAcceptSeconds,
    tcpNoDelay: tcpNoDelay,
    initialReadBufferBytes: initialReadBufferBytes,
    maxRequestBodySize: maxRequestBodySize,
    readTimeoutMs: readTimeoutMs,
    maxRequestLineSize: maxRequestLineSize,
    maxHeaderLineSize: maxHeaderLineSize,
    maxHeaderBytes: maxHeaderBytes,
    maxHeaderCount: maxHeaderCount,
    maxWsFrameBytes: maxWsFrameBytes,
    maxWsMessageBytes: maxWsMessageBytes,
    trustedProxyCidrs: trustedProxyCidrs,
    trustedForwardedHeaders: trustedForwardedHeaders
  )
  HttpServer(
    config: config,
    handler: handler,
    running: false,
    boundPort: 0,
    connGroup: newTaskGroup(epCollectAll),
    acceptStopSignal: nil,
    shutdownStarted: false
  )

proc getPort*(server: HttpServer): int =
  ## Return the effective server port.
  server.boundPort

proc bindAndListen*(server: HttpServer) =
  ## Bind and listen. Call before start().
  server.listener = tcpListen(
    server.config.host,
    server.config.port,
    reusePort = server.config.reusePort,
    deferAcceptSeconds = server.config.deferAcceptSeconds,
    noDelay = server.config.tcpNoDelay
  )
  # Get the actual bound port
  var localAddr: Sockaddr_in
  var addrLen: SockLen = sizeof(localAddr).SockLen
  let rc = getsockname(server.listener.fd, cast[ptr SockAddr](addr localAddr), addr addrLen)
  if rc == 0:
    server.boundPort = nativesockets.ntohs(localAddr.sin_port).int
  else:
    server.boundPort = server.config.port

proc stop*(server: HttpServer) =
  ## Stop accepting and wake the server lifecycle task.
  server.running = false
  if server.listener != nil and not server.listener.closed:
    server.listener.close()
  if server.acceptStopSignal != nil and not server.acceptStopSignal.finished:
    server.acceptStopSignal.complete()

proc onStart*(server: HttpServer, cb: proc()) =
  ## Register a callback invoked once when the server starts accepting.
  server.onStartCallbacks.add cb

proc onShutdown*(server: HttpServer, cb: proc()) =
  ## Register a callback invoked once when graceful shutdown begins.
  server.onShutdownCallbacks.add cb
