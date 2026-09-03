## HTTP/1.1 Server Implementation
##
## Parses HTTP/1.1 requests and writes responses over an AsyncStream.
## Supports keep-alive connections and chunked/fixed-length bodies.

import std/[strutils, tables]
import cps/runtime
import cps/transform
import cps/io/streams
import cps/io/tcp
import cps/io/buffered
import cps/io/timeouts
import ./types

type
  Http1RequestError = object of CatchableError
    statusCode: int

  ParseRequestResult = object
    ok: bool
    req: HttpRequest
    statusCode: int
    errBody: string
    closeConn: bool
    hasConnectionClose: bool
    hasConnectionKeepAlive: bool
    requestBytes: int

  Http1ServerConnection* = object
    stream*: AsyncStream
    reader*: BufferedReader
    config*: HttpServerConfig

  Http1SpecialHeader = enum
    h1hOther, h1hHost, h1hExpect, h1hConnection,
    h1hContentLength, h1hTransferEncoding

const
  H1Empty200KeepAliveResponse =
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
  H1Empty200CloseResponse =
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

proc classifySpecialHeader(name: ByteView): Http1SpecialHeader {.inline.} =
  ## Dispatch common semantic headers by length first. This keeps arbitrary
  ## extension headers on the generic path while avoiding five full
  ## case-insensitive comparisons for every header line.
  case name.len
  of 4:
    if eqCaseInsensitive(name, "host"): h1hHost else: h1hOther
  of 6:
    if eqCaseInsensitive(name, "expect"): h1hExpect else: h1hOther
  of 10:
    if eqCaseInsensitive(name, "connection"): h1hConnection else: h1hOther
  of 14:
    if eqCaseInsensitive(name, "content-length"): h1hContentLength else: h1hOther
  of 17:
    if eqCaseInsensitive(name, "transfer-encoding"): h1hTransferEncoding else: h1hOther
  else:
    h1hOther

proc raiseRequestError(statusCode: int, msg: string) =
  var err = newException(Http1RequestError, msg)
  err.statusCode = statusCode
  raise err

proc applyReadTimeout[T](fut: CpsFuture[T], timeoutMs: int): CpsFuture[T] {.inline.} =
  if timeoutMs > 0:
    # Fast path: if data is already buffered, the future completes synchronously.
    # Skip the expensive timeout wrapper (timer + atomic flag + closures).
    if fut.finished():
      return fut
    return withTimeout(fut, timeoutMs)
  fut

proc headerHasToken(value, token: string): bool =
  ## Zero-allocation comma-separated token search (case-insensitive).
  var i = 0
  while i < value.len:
    # Skip leading whitespace
    while i < value.len and (value[i] == ' ' or value[i] == '\t'): inc i
    let start = i
    # Find end of token (next comma or end)
    while i < value.len and value[i] != ',': inc i
    # Trim trailing whitespace
    var tokenEnd = i - 1
    while tokenEnd >= start and (value[tokenEnd] == ' ' or value[tokenEnd] == '\t'): dec tokenEnd
    let tokenLen = tokenEnd - start + 1
    if tokenLen == token.len:
      var match = true
      for j in 0 ..< tokenLen:
        if toLowerAscii(value[start + j]) != toLowerAscii(token[j]):
          match = false
          break
      if match: return true
    if i < value.len: inc i  # skip comma
  false

proc headerHasToken(value: ByteView, token: string): bool =
  var i = 0
  while i < value.len:
    while i < value.len and value[i] in {' ', '\t'}: inc i
    let start = i
    while i < value.len and value[i] != ',': inc i
    var tokenEnd = i
    while tokenEnd > start and value[tokenEnd - 1] in {' ', '\t'}: dec tokenEnd
    if tokenEnd - start == token.len:
      var matched = true
      for j in 0 ..< token.len:
        if toLowerAscii(value[start + j]) != toLowerAscii(token[j]):
          matched = false
          break
      if matched: return true
    if i < value.len: inc i
  false

proc headersHaveToken(headers: openArray[(string, string)],
                      name, token: string): bool =
  for (k, v) in headers:
    if eqCaseInsensitive(k, name) and headerHasToken(v, token):
      return true
  false

proc headersContainName(headers: openArray[(string, string)], name: string): bool =
  for (k, _) in headers:
    if eqCaseInsensitive(k, name):
      return true
  false

proc removeHeadersByName(headers: var seq[(string, string)], name: string) =
  var i = 0
  while i < headers.len:
    if eqCaseInsensitive(headers[i][0], name):
      headers.delete(i)
    else:
      inc i

proc parseContentLengthValue(value: string, parsed: var int): bool =
  if value.len == 0:
    return false
  for ch in value:
    if ch notin Digits:
      return false
  let n =
    try:
      parseBiggestInt(value)
    except ValueError:
      return false
  if n < 0 or n > BiggestInt(high(int)):
    return false
  parsed = int(n)
  true

proc parseContentLengthValue(value: ByteView, parsed: var int): bool =
  if value.len == 0: return false
  var n = 0
  for ch in value:
    if ch notin Digits: return false
    let digit = ord(ch) - ord('0')
    if n > (high(int) - digit) div 10: return false
    n = n * 10 + digit
  parsed = n
  true

proc parseTransferEncodingTokens(value: string, tokens: var seq[string]): bool =
  tokens.setLen(0)
  if value.len == 0:
    return false
  for part in value.split(','):
    let token = part.strip().toLowerAscii
    if token.len == 0:
      return false
    if not isValidHeaderName(token):
      return false
    tokens.add token
  # This implementation only supports pure chunked transfer-coding.
  tokens.len == 1 and tokens[0] == "chunked"

proc parseCommaTokens(value: string, tokens: var seq[string]): bool =
  tokens.setLen(0)
  if value.len == 0:
    return false
  for part in value.split(','):
    let token = part.strip().toLowerAscii
    if token.len == 0:
      return false
    if not isValidHeaderName(token):
      return false
    tokens.add token
  tokens.len > 0

proc parseHexChunkSize(token: string, parsed: var int): bool =
  if token.len == 0:
    return false
  var n: uint64 = 0
  for ch in token:
    var v = 0'u64
    if ch in {'0' .. '9'}:
      v = uint64(ord(ch) - ord('0'))
    elif ch in {'a' .. 'f'}:
      v = uint64(ord(ch) - ord('a') + 10)
    elif ch in {'A' .. 'F'}:
      v = uint64(ord(ch) - ord('A') + 10)
    else:
      return false
    if n > (uint64(high(int)) shr 4):
      return false
    n = (n shl 4) or v
  if n > uint64(high(int)):
    return false
  parsed = int(n)
  true

type
  ByteRange = object
    start: int
    len: int

  HeaderParseResult = object
    ok: bool
    statusCode: int
    errBody: string
    meth: ByteRange
    path: ByteRange
    httpVersion: ByteRange
    headers: ByteRange
    headerCount: int
    requestBytes: int
    hasConnectionClose: bool
    hasConnectionKeepAlive: bool
    parsedContentLength: int
    sawContentLength: bool
    hasChunkedTransfer: bool
    hasExpect100Continue: bool

proc parseHeaderBlock(headerBlock: ByteView, config: HttpServerConfig): HeaderParseResult =
  ## Parse a complete header block (request line + headers) synchronously.
  ## The headerBlock does NOT include the trailing \r\n\r\n.
  if headerBlock.len == 0:
    return HeaderParseResult(statusCode: 0)  # signals close

  # Find the first \r\n to separate request line from headers
  var lineEnd = 0
  while lineEnd < headerBlock.len - 1:
    if headerBlock[lineEnd] == '\r' and headerBlock[lineEnd + 1] == '\n':
      break
    inc lineEnd
  if lineEnd >= headerBlock.len - 1:
    # No \r\n found — whole block is request line with no headers
    lineEnd = headerBlock.len

  let requestLineLen = lineEnd
  if config.maxRequestLineSize > 0 and requestLineLen > config.maxRequestLineSize:
    return HeaderParseResult(ok: false, statusCode: 414, errBody: "URI Too Long")

  # Parse request line: METHOD SP path SP version
  let sp1 = headerBlock.find(' ')
  if sp1 <= 0 or sp1 >= lineEnd:
    return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
  let sp2 = headerBlock.find(' ', sp1 + 1)
  if sp2 < 0 or sp2 >= lineEnd or sp2 == sp1 + 1:
    return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")

  result.meth = ByteRange(start: 0, len: sp1)
  result.path = ByteRange(start: sp1 + 1, len: sp2 - sp1 - 1)
  result.httpVersion = ByteRange(start: sp2 + 1, len: lineEnd - sp2 - 1)

  let meth = headerBlock[result.meth.start ..< result.meth.start + result.meth.len]
  let path = headerBlock[result.path.start ..< result.path.start + result.path.len]
  let httpVersion = headerBlock[result.httpVersion.start ..< result.httpVersion.start + result.httpVersion.len]
  if meth.len == 0 or not isValidHeaderName(meth):
    return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
  if path.len == 0:
    return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
  for c in path:
    if ord(c) < 0x21 or ord(c) == 0x7F:
      return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
  if httpVersion.len == 0 or httpVersion.find(' ') >= 0:
    return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
  if httpVersion != "HTTP/1.1" and httpVersion != "HTTP/1.0":
    if httpVersion.startsWith("HTTP/"):
      return HeaderParseResult(ok: false, statusCode: 505, errBody: "HTTP Version Not Supported")
    return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")

  # Parse headers from the remaining lines
  var headerCount = 0
  var totalHeaderBytes = 0
  var hostHeaderCount = 0
  var pos = lineEnd + 2  # skip past \r\n of request line
  var expectTokenCount = 0
  var transferTokenCount = 0
  let headersStart = lineEnd + 2

  while pos < headerBlock.len:
    # Find end of this header line
    var hEnd = pos
    while hEnd < headerBlock.len - 1:
      if headerBlock[hEnd] == '\r' and headerBlock[hEnd + 1] == '\n':
        break
      inc hEnd
    if hEnd >= headerBlock.len - 1:
      hEnd = headerBlock.len  # last line without trailing \r\n

    let lineLen = hEnd - pos
    if lineLen == 0:
      # Empty line — end of headers (shouldn't happen since readUntilHeaderEnd
      # stops at \r\n\r\n, but handle gracefully)
      break

    inc headerCount
    totalHeaderBytes += lineLen
    if config.maxHeaderCount > 0 and headerCount > config.maxHeaderCount:
      return HeaderParseResult(ok: false, statusCode: 431, errBody: "Request Header Fields Too Large")
    if config.maxHeaderLineSize > 0 and lineLen > config.maxHeaderLineSize:
      return HeaderParseResult(ok: false, statusCode: 431, errBody: "Request Header Fields Too Large")
    if config.maxHeaderBytes > 0 and totalHeaderBytes > config.maxHeaderBytes:
      return HeaderParseResult(ok: false, statusCode: 431, errBody: "Request Header Fields Too Large")

    if headerBlock[pos] == ' ' or headerBlock[pos] == '\t':
      return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")

    # Find colon
    var colonPos = pos
    while colonPos < hEnd and headerBlock[colonPos] != ':':
      inc colonPos
    if colonPos >= hEnd or colonPos == pos:
      return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")

    let rawKey = headerBlock[pos ..< colonPos]
    # Check no trailing whitespace in key
    if rawKey[^1] == ' ' or rawKey[^1] == '\t':
      return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")

    # Extract and strip value
    var valStart = colonPos + 1
    while valStart < hEnd and (headerBlock[valStart] == ' ' or headerBlock[valStart] == '\t'):
      inc valStart
    var valEnd = hEnd - 1
    while valEnd >= valStart and (headerBlock[valEnd] == ' ' or headerBlock[valEnd] == '\t'):
      dec valEnd
    let val =
      if valStart <= valEnd: headerBlock[valStart .. valEnd]
      else: ByteView()

    if not validateHeaderPair(rawKey, val):
      return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")

    case classifySpecialHeader(rawKey)
    of h1hHost:
      if val.len == 0:
        return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
      inc hostHeaderCount
    of h1hContentLength:
      var parsedLen = 0
      if not parseContentLengthValue(val, parsedLen):
        return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
      if result.sawContentLength and parsedLen != result.parsedContentLength:
        return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
      result.sawContentLength = true
      result.parsedContentLength = parsedLen
    of h1hTransferEncoding:
      var tokenStart = 0
      while tokenStart < val.len:
        while tokenStart < val.len and val[tokenStart] in {' ', '\t'}: inc tokenStart
        var tokenEnd = tokenStart
        while tokenEnd < val.len and val[tokenEnd] != ',': inc tokenEnd
        var trimmedEnd = tokenEnd
        while trimmedEnd > tokenStart and val[trimmedEnd - 1] in {' ', '\t'}: dec trimmedEnd
        let token = val[tokenStart .. trimmedEnd - 1]
        if token.len == 0 or not isValidHeaderName(token) or
            not eqCaseInsensitive(token, "chunked"):
          return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
        inc transferTokenCount
        tokenStart = tokenEnd + 1
    of h1hExpect:
      var tokenStart = 0
      while tokenStart < val.len:
        while tokenStart < val.len and val[tokenStart] in {' ', '\t'}: inc tokenStart
        var tokenEnd = tokenStart
        while tokenEnd < val.len and val[tokenEnd] != ',': inc tokenEnd
        var trimmedEnd = tokenEnd
        while trimmedEnd > tokenStart and val[trimmedEnd - 1] in {' ', '\t'}: dec trimmedEnd
        let token = val[tokenStart .. trimmedEnd - 1]
        if token.len == 0 or not eqCaseInsensitive(token, "100-continue"):
          return HeaderParseResult(ok: false, statusCode: 417, errBody: "Expectation Failed")
        inc expectTokenCount
        tokenStart = tokenEnd + 1
    of h1hConnection:
      if headerHasToken(val, "close"):
        result.hasConnectionClose = true
      if headerHasToken(val, "keep-alive"):
        result.hasConnectionKeepAlive = true
    of h1hOther:
      discard
    pos = hEnd + 2  # skip \r\n

  if httpVersion == "HTTP/1.1" and hostHeaderCount != 1:
    return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
  if httpVersion == "HTTP/1.0" and hostHeaderCount > 1:
    return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")

  # Process expect header
  if expectTokenCount > 0:
    result.hasExpect100Continue = true
    if result.hasExpect100Continue and
       result.sawContentLength and
       config.maxRequestBodySize > 0 and
       result.parsedContentLength > config.maxRequestBodySize:
      return HeaderParseResult(ok: false, statusCode: 413, errBody: "Payload Too Large")

  if transferTokenCount > 1:
    return HeaderParseResult(ok: false, statusCode: 400, errBody: "Bad Request")
  result.hasChunkedTransfer = transferTokenCount == 1
  result.headers = ByteRange(start: headersStart, len: headerBlock.len - headersStart)
  result.headerCount = headerCount
  result.requestBytes = headerBlock.len + 4

  result.ok = true

proc makeBorrowedRequest(stream: AsyncStream, reader: BufferedReader,
                         config: HttpServerConfig, remoteAddr: string,
                         hdr: HeaderParseResult, bodyStart, bodyLen: int): HttpRequest {.inline.} =
  let base = reader.bufferData()
  HttpRequest(
    meth: view(base, hdr.meth.start, hdr.meth.len),
    path: view(base, hdr.path.start, hdr.path.len),
    httpVersion: view(base, hdr.httpVersion.start, hdr.httpVersion.len),
    headers: rawHttp1Headers(
      view(base, hdr.headers.start, hdr.headers.len), hdr.headerCount),
    body: view(base, bodyStart, bodyLen),
    remoteAddr: remoteAddr,
    stream: stream,
    reader: reader,
    context: nil,
    maxWsFrameBytes: config.maxWsFrameBytes,
    maxWsMessageBytes: config.maxWsMessageBytes
  )

proc fillTo(reader: BufferedReader, needed, timeoutMs: int): CpsFuture[bool] {.cps.} =
  while reader.available < needed:
    try:
      let filled = await applyReadTimeout(reader.fillBuffer(), timeoutMs)
      if not filled:
        return false
    except CatchableError:
      raise
  return true

proc findBufferedCrlf(reader: BufferedReader, start: int): int {.inline.} =
  var i = start
  while i + 1 < reader.available:
    if reader.bufferedChar(i) == '\r' and reader.bufferedChar(i + 1) == '\n':
      return i
    inc i
  -1

proc parseHexChunkSize(value: ByteView, parsed: var int): bool =
  var first = 0
  var last = value.len
  while first < last and value[first] in {' ', '\t'}: inc first
  while last > first and value[last - 1] in {' ', '\t'}: dec last
  let semi = value.find(';', first)
  if semi >= 0 and semi < last: last = semi
  if first >= last: return false
  var n: uint64 = 0
  for i in first ..< last:
    let ch = value[i]
    var digit: uint64
    if ch in {'0' .. '9'}: digit = uint64(ord(ch) - ord('0'))
    elif ch in {'a' .. 'f'}: digit = uint64(ord(ch) - ord('a') + 10)
    elif ch in {'A' .. 'F'}: digit = uint64(ord(ch) - ord('A') + 10)
    else: return false
    if n > (uint64(high(int)) shr 4): return false
    n = (n shl 4) or digit
  parsed = int(n)
  true

proc parseRequestResultWithBody(stream: AsyncStream, reader: BufferedReader,
                                config: HttpServerConfig,
                                remoteAddr: string,
                                hdr: HeaderParseResult): CpsFuture[ParseRequestResult] {.cps.} =
  ## Buffer the complete message once, then expose fields and body as views.
  ## Chunk framing is removed in place; no body strings or part sequences exist.
  if hdr.hasChunkedTransfer and hdr.sawContentLength:
    return ParseRequestResult(statusCode: 400, errBody: "Bad Request")

  if hdr.hasExpect100Continue:
    try:
      await stream.write("HTTP/1.1 100 Continue\r\n\r\n")
    except CatchableError:
      return ParseRequestResult(closeConn: true)

  var requestBytes = hdr.requestBytes
  var bodyLen = 0
  let bodyStart = hdr.requestBytes

  if hdr.hasChunkedTransfer:
    var source = bodyStart
    var destination = bodyStart
    var headerCount = hdr.headerCount
    var trailerBytes = 0
    while true:
      var lineEnd = reader.findBufferedCrlf(source)
      while lineEnd < 0:
        try:
          let filled = await reader.fillTo(reader.available + 1, config.readTimeoutMs)
          if not filled:
            return ParseRequestResult(closeConn: true)
        except TimeoutError:
          return ParseRequestResult(statusCode: 408, errBody: "Request Timeout")
        except CatchableError:
          return ParseRequestResult(closeConn: true)
        lineEnd = reader.findBufferedCrlf(source)

      var chunkSize = 0
      let base = reader.bufferData()
      if not parseHexChunkSize(view(base, source, lineEnd - source), chunkSize):
        return ParseRequestResult(statusCode: 400, errBody: "Bad Request")
      source = lineEnd + 2

      if chunkSize == 0:
        while true:
          lineEnd = reader.findBufferedCrlf(source)
          while lineEnd < 0:
            try:
              let filled = await reader.fillTo(reader.available + 1, config.readTimeoutMs)
              if not filled:
                return ParseRequestResult(closeConn: true)
            except TimeoutError:
              return ParseRequestResult(statusCode: 408, errBody: "Request Timeout")
            except CatchableError:
              return ParseRequestResult(closeConn: true)
            lineEnd = reader.findBufferedCrlf(source)
          if lineEnd == source:
            source += 2
            break
          let lineLen = lineEnd - source
          let current = reader.bufferData()
          if current[source] in {' ', '\t'}:
            return ParseRequestResult(statusCode: 400, errBody: "Bad Request")
          var colon = source
          while colon < lineEnd and current[colon] != ':': inc colon
          if colon == source or colon == lineEnd or current[colon - 1] in {' ', '\t'}:
            return ParseRequestResult(statusCode: 400, errBody: "Bad Request")
          var valueStart = colon + 1
          while valueStart < lineEnd and current[valueStart] in {' ', '\t'}: inc valueStart
          var valueEnd = lineEnd
          while valueEnd > valueStart and current[valueEnd - 1] in {' ', '\t'}: dec valueEnd
          if not validateHeaderPair(
              view(current, source, colon - source),
              view(current, valueStart, valueEnd - valueStart)):
            return ParseRequestResult(statusCode: 400, errBody: "Bad Request")
          inc headerCount
          trailerBytes += lineLen
          if (config.maxHeaderCount > 0 and headerCount > config.maxHeaderCount) or
              (config.maxHeaderLineSize > 0 and lineLen > config.maxHeaderLineSize) or
              (config.maxHeaderBytes > 0 and trailerBytes > config.maxHeaderBytes):
            return ParseRequestResult(statusCode: 431, errBody: "Request Header Fields Too Large")
          source = lineEnd + 2
        requestBytes = source
        break

      if config.maxRequestBodySize > 0 and bodyLen + chunkSize > config.maxRequestBodySize:
        return ParseRequestResult(statusCode: 413, errBody: "Payload Too Large")
      try:
        let filled = await reader.fillTo(source + chunkSize + 2, config.readTimeoutMs)
        if not filled:
          return ParseRequestResult(closeConn: true)
      except TimeoutError:
        return ParseRequestResult(statusCode: 408, errBody: "Request Timeout")
      except CatchableError:
        return ParseRequestResult(closeConn: true)
      let current = reader.bufferData()
      if current[source + chunkSize] != '\r' or current[source + chunkSize + 1] != '\n':
        return ParseRequestResult(statusCode: 400, errBody: "Bad Request")
      if chunkSize > 0:
        moveMem(addr current[destination], addr current[source], chunkSize)
      destination += chunkSize
      bodyLen += chunkSize
      source += chunkSize + 2
  else:
    bodyLen = hdr.parsedContentLength
    if config.maxRequestBodySize > 0 and bodyLen > config.maxRequestBodySize:
      return ParseRequestResult(statusCode: 413, errBody: "Payload Too Large")
    requestBytes += bodyLen
    try:
      let filled = await reader.fillTo(requestBytes, config.readTimeoutMs)
      if not filled:
        return ParseRequestResult(closeConn: true)
    except TimeoutError:
      return ParseRequestResult(statusCode: 408, errBody: "Request Timeout")
    except CatchableError:
      return ParseRequestResult(closeConn: true)

  let req = makeBorrowedRequest(
    stream, reader, config, remoteAddr, hdr, bodyStart, bodyLen)
  return ParseRequestResult(
    ok: true, req: req, hasConnectionClose: hdr.hasConnectionClose,
    hasConnectionKeepAlive: hdr.hasConnectionKeepAlive,
    requestBytes: requestBytes)

proc processHeaderBlockPoll(headerBlock: ByteView, config: HttpServerConfig,
                            stream: AsyncStream, reader: BufferedReader,
                            remoteAddr: string,
                            parsed: ptr ParseRequestResult): CpsFuture[ParseRequestResult] =
  ## Process a complete header block into a ParseRequestResult.
  ## Returns nil with `parsed` populated for synchronous results. Body-bearing
  ## requests return the future that will finish the remaining async work.
  if headerBlock.len == 0:
    parsed[] = ParseRequestResult(closeConn: true)
    return nil

  let hdr = parseHeaderBlock(headerBlock, config)
  if not hdr.ok:
    if hdr.statusCode == 0:
      parsed[] = ParseRequestResult(closeConn: true)
    else:
      parsed[] = ParseRequestResult(statusCode: hdr.statusCode, errBody: hdr.errBody)
    return nil

  # Check if body reading is needed
  let needsBody = hdr.hasChunkedTransfer or
                  (hdr.sawContentLength and hdr.parsedContentLength > 0) or
                  hdr.hasExpect100Continue
  if needsBody:
    return parseRequestResultWithBody(stream, reader, config, remoteAddr, hdr)

  # No body — fast path: return pre-completed future
  let req = makeBorrowedRequest(stream, reader, config, remoteAddr, hdr, 0, 0)
  parsed[] = ParseRequestResult(ok: true, req: req,
    hasConnectionClose: hdr.hasConnectionClose,
    hasConnectionKeepAlive: hdr.hasConnectionKeepAlive,
    requestBytes: hdr.requestBytes)
  return nil

proc processHeaderBlock(headerBlock: ByteView, config: HttpServerConfig,
                        stream: AsyncStream, reader: BufferedReader,
                        remoteAddr: string): CpsFuture[ParseRequestResult] =
  ## Compatibility wrapper for callers that always consume a Future.
  var parsed: ParseRequestResult
  result = processHeaderBlockPoll(
    headerBlock, config, stream, reader, remoteAddr, addr parsed)
  if result.isNil:
    result = completedFuture(parsed)

proc parseRequestPending(stream: AsyncStream, reader: BufferedReader,
                         config: HttpServerConfig,
                         remoteAddr: string,
                         initialFill: CpsFuture[bool] = nil): CpsFuture[ParseRequestResult] {.cps.} =
  let maxHeaderSize =
    if config.maxHeaderBytes > 0: config.maxHeaderBytes
    else: 65536
  if initialFill != nil:
    try:
      let filled = await applyReadTimeout(initialFill, config.readTimeoutMs)
      if not filled:
        return ParseRequestResult(closeConn: true)
    except TimeoutError:
      return ParseRequestResult(statusCode: 408, errBody: "Request Timeout")
    except CatchableError:
      return ParseRequestResult(closeConn: true)
  while true:
    let headerEnd = reader.searchHeaderEndOffset()
    if headerEnd >= 0:
      var parsed: ParseRequestResult
      let headerBlock = view(reader.bufferData(), headerEnd)
      let bodyFut = processHeaderBlockPoll(
        headerBlock, config, stream, reader, remoteAddr, addr parsed)
      if bodyFut.isNil: return parsed
      return await bodyFut
    if reader.available > maxHeaderSize:
      return ParseRequestResult(
        statusCode: 431, errBody: "Request Header Fields Too Large")
    if reader.atEof():
      return ParseRequestResult(closeConn: true)
    try:
      let filled = await applyReadTimeout(reader.fillBuffer(), config.readTimeoutMs)
      if not filled:
        return ParseRequestResult(closeConn: true)
    except TimeoutError:
      return ParseRequestResult(statusCode: 408, errBody: "Request Timeout")
    except CatchableError:
      return ParseRequestResult(closeConn: true)

proc parseRequestResultPoll(stream: AsyncStream, reader: BufferedReader,
                            config: HttpServerConfig, remoteAddr: string,
                            parsed: ptr ParseRequestResult): CpsFuture[ParseRequestResult] =
  ## Parse an HTTP/1.1 request. Avoids CPS env allocation for the common case
  ## and returns nil with `parsed` populated when it finishes synchronously.
  # Ultra-fast path: parse directly from the connection buffer. Consumption is
  # deferred until the response has completed, which leases all request views.
  var idx = reader.searchHeaderEndOffset()
  if idx >= 0:
    return processHeaderBlockPoll(
      view(reader.bufferData(), idx), config, stream, reader, remoteAddr, parsed)

  # Try one sync fill, then check again (common for keep-alive)
  if not reader.atEof():
    case reader.pollFillBuffer()
    of bfpData:
      idx = reader.searchHeaderEndOffset()
      if idx >= 0:
        return processHeaderBlockPoll(
          view(reader.bufferData(), idx), config, stream, reader, remoteAddr, parsed)
    of bfpEof, bfpError:
      parsed[] = ParseRequestResult(closeConn: true)
      return nil
    of bfpWouldBlock:
      # The non-blocking read already established EAGAIN. Arm readiness
      # directly instead of repeating the same syscall in fillBuffer().
      return parseRequestPending(stream, reader, config, remoteAddr,
        reader.waitFillBuffer())
    of bfpUnsupported:
      let fillFut = reader.fillBuffer()
      if fillFut.finished():
        if fillFut.hasError() or not fillFut.read():
          parsed[] = ParseRequestResult(closeConn: true)
          return nil
        idx = reader.searchHeaderEndOffset()
        if idx >= 0:
          return processHeaderBlockPoll(
            view(reader.bufferData(), idx), config, stream, reader, remoteAddr, parsed)
      else:
        # Continue the read already registered by fillBuffer(). Starting
        # another pending fill would orphan the first future chain.
        return parseRequestPending(stream, reader, config, remoteAddr, fillFut)

  # EOF with no data
  if reader.atEof():
    parsed[] = ParseRequestResult(closeConn: true)
    return nil

  return parseRequestPending(stream, reader, config, remoteAddr)

proc parseRequestResult(stream: AsyncStream, reader: BufferedReader,
                        config: HttpServerConfig,
                        remoteAddr: string = ""): CpsFuture[ParseRequestResult] =
  ## Future-returning compatibility API used outside the connection driver.
  var parsed: ParseRequestResult
  result = parseRequestResultPoll(stream, reader, config, remoteAddr, addr parsed)
  if result.isNil:
    result = completedFuture(parsed)

proc parseRequest*(stream: AsyncStream, reader: BufferedReader,
                   config: HttpServerConfig,
                   remoteAddr: string = ""): CpsFuture[HttpRequest] {.cps.} =
  ## Parse an HTTP/1.1 request from the stream.
  let parsed = await parseRequestResult(stream, reader, config, remoteAddr)
  if parsed.ok:
    return parsed.req
  if parsed.statusCode != 0:
    raiseRequestError(parsed.statusCode, parsed.errBody)
  raise newException(streams.AsyncIoError, "Connection closed")

proc statusProhibitsBody(statusCode: int): bool {.inline.} =
  (statusCode >= 100 and statusCode < 200) or statusCode == 204 or statusCode == 304

proc addInt(s: var string, n: int) {.inline.} =
  ## Append integer to string without allocating a temporary `$n`.
  if n == 0:
    s.add '0'
    return
  var val = n
  let start = s.len
  while val > 0:
    s.add char(ord('0') + val mod 10)
    val = val div 10
  # Reverse the appended digits in-place
  var lo = start
  var hi = s.len - 1
  while lo < hi:
    swap(s[lo], s[hi])
    inc lo
    dec hi

proc addView(s: var string, value: ByteView) {.inline.} =
  let oldLen = s.len
  s.setLen(oldLen + value.len)
  if value.len > 0:
    copyMem(addr s[oldLen], value.data, value.len)

proc statusLine(code: int): string {.inline.} =
  ## Return pre-computed status line prefix for common codes.
  case code
  of 200: "HTTP/1.1 200 OK\r\n"
  of 201: "HTTP/1.1 201 Created\r\n"
  of 204: "HTTP/1.1 204 No Content\r\n"
  of 301: "HTTP/1.1 301 Moved Permanently\r\n"
  of 302: "HTTP/1.1 302 Found\r\n"
  of 304: "HTTP/1.1 304 Not Modified\r\n"
  of 400: "HTTP/1.1 400 Bad Request\r\n"
  of 404: "HTTP/1.1 404 Not Found\r\n"
  of 405: "HTTP/1.1 405 Method Not Allowed\r\n"
  of 500: "HTTP/1.1 500 Internal Server Error\r\n"
  else:
    var s = "HTTP/1.1 "
    s.addInt(code)
    s.add ' '
    s.add statusMessage(code)
    s.add "\r\n"
    s

proc buildResponseInto(resp: HttpResponseBuilder, sendBody: bool,
                       bodyLengthHint: int, output: var string) =
  output.setLen(0)
  if not validateResponseHeaders(resp.headers):
    let body = "Internal Server Error"
    output.add "HTTP/1.1 500 Internal Server Error\r\nContent-Length: "
    output.addInt(body.len)
    output.add "\r\nConnection: close\r\n\r\n"
    if sendBody:
      output.add body
    return

  let noBody = statusProhibitsBody(resp.statusCode)
  let resetContentNoPayload = resp.statusCode == 205
  let representationLen =
    if bodyLengthHint >= 0: bodyLengthHint
    else: resp.body.len
  let bodyStr: ByteView =
    if noBody or resetContentNoPayload or not sendBody: ByteView()
    else: resp.body

  # Pre-allocate: status line + headers + body
  output.add statusLine(resp.statusCode)

  for (k, v) in resp.headers:
    if eqCaseInsensitive(k, "content-length") or eqCaseInsensitive(k, "transfer-encoding"):
      continue
    output.add k
    output.add ": "
    output.add v
    output.add "\r\n"
  if resetContentNoPayload:
    output.add "Content-Length: 0\r\n"
  elif not noBody:
    output.add "Content-Length: "
    output.addInt(representationLen)
    output.add "\r\n"

  output.add "\r\n"
  output.addView(bodyStr)

proc buildResponseStringImpl(resp: HttpResponseBuilder,
                             sendBody: bool,
                             bodyLengthHint: int): string =
  result = newStringOfCap(256 + resp.body.len)
  buildResponseInto(resp, sendBody, bodyLengthHint, result)

proc buildResponseString*(resp: HttpResponseBuilder): string =
  ## Build the HTTP/1.1 response string from a response builder.
  buildResponseStringImpl(resp, sendBody = true, bodyLengthHint = -1)

proc writeResponse*(stream: AsyncStream, resp: HttpResponseBuilder,
                    sendBody: bool = true,
                    bodyLengthHint: int = -1): CpsVoidFuture =
  ## Write an HTTP/1.1 response to the stream.
  let respStr = buildResponseStringImpl(resp, sendBody, bodyLengthHint)
  stream.write(respStr)

proc writeResponseBuffered(stream: AsyncStream, resp: HttpResponseBuilder,
                           output: var string, sendBody: bool = true,
                           bodyLengthHint: int = -1): CpsVoidFuture =
  let borrowBody = sendBody and resp.body.len > 0 and
    not statusProhibitsBody(resp.statusCode) and
    validateResponseHeaders(resp.headers)
  if borrowBody:
    buildResponseInto(resp, false, resp.body.len, output)
    return stream.writevBorrowed(
      addr output[0], output.len, resp.body.data, resp.body.len)
  buildResponseInto(resp, sendBody, bodyLengthHint, output)
  stream.writeBorrowed(addr output[0], output.len)

proc headBodyLengthHint(resp: HttpResponseBuilder): int =
  ## For HEAD requests, extract Content-Length from headers if present
  ## (e.g. set by router HEAD auto-gen), else fall back to body length.
  let clVal = resp.getResponseHeader("content-length")
  if clVal.len > 0:
    var parsed = 0
    if parseContentLengthValue(clVal, parsed):
      return parsed
  resp.body.len

proc handleHttp1Connection*(stream: AsyncStream, config: HttpServerConfig,
                            handler: HttpHandler,
                            remoteAddr: string = ""): CpsVoidFuture {.cps.} =
  ## Handle an HTTP/1.1 connection: parse requests in a loop, call the
  ## handler, and write responses. Honors Connection: close.
  let initialBufferBytes =
    if config.initialReadBufferBytes > 0: config.initialReadBufferBytes
    else: 2048
  let reader = newBufferedReader(stream, initialBufferBytes)
  var responseBuffer = newStringOfCap(256)
  var canCloseImmediately = false
  while true:
    var req: HttpRequest
    var hasRequest = false
    var closeConn = false
    var parseErrStatus = 0
    var parseErrBody = ""
    var parsed: ParseRequestResult
    let parsedFut = parseRequestResultPoll(stream, reader, config, remoteAddr, addr parsed)
    if parsedFut != nil:
      parsed = await parsedFut
    if parsed.ok:
      req = parsed.req
      hasRequest = true
      # Advance logical input now while retaining the leased bytes in-place.
      # The next fill/compaction cannot happen until this handler completes.
      reader.consumeBuffered(parsed.requestBytes)
    elif parsed.statusCode != 0:
      parseErrStatus = parsed.statusCode
      parseErrBody = parsed.errBody
    else:
      closeConn = parsed.closeConn

    if parseErrStatus != 0:
      try:
        await writeResponseBuffered(stream,
          newResponse(parseErrStatus, parseErrBody, @[("Connection", "close")]),
          responseBuffer)
      except CatchableError:
        discard
      break

    if closeConn or not hasRequest:
      break

    var resp: HttpResponseBuilder
    var wsHandlerFailure = false
    try:
      resp = await handler(req)
    except CatchableError:
      if not req.context.isNil and req.context.getOrDefault("ws_upgraded") == "1":
        wsHandlerFailure = true
      else:
        resp = newResponse(500, "Internal Server Error", @[("Connection", "close")])

    if wsHandlerFailure:
      break

    if resp.control == rcHandled or resp.statusCode == 0:
      break  # SSE/WS/chunked handler already wrote to stream

    let reqClose = parsed.hasConnectionClose
    let reqKeepAlive = parsed.hasConnectionKeepAlive
    let shouldCloseAfterResponse = reqClose or (req.httpVersion == "HTTP/1.0" and not reqKeepAlive)
    let isHeadRequest = eqCaseInsensitive(req.meth, "HEAD")
    let plainOkResponse = resp.statusCode == 200 and resp.headers.len == 0 and
                          not isHeadRequest
    if shouldCloseAfterResponse and not plainOkResponse:
      removeHeadersByName(resp.headers, "connection")
      resp.headers.add(("Connection", "close"))
    elif not headersContainName(resp.headers, "connection"):
      if req.httpVersion == "HTTP/1.0":
        if reqKeepAlive:
          resp.headers.add(("Connection", "keep-alive"))
        else:
          resp.headers.add(("Connection", "close"))
      else:
        if reqClose:
          resp.headers.add(("Connection", "close"))

    var writeFailed = false
    try:
      # Common plain-response path: avoid header validation, iteration, and
      # response mutation when no custom metadata is present.
      if plainOkResponse:
        if resp.body.len == 0:
          if shouldCloseAfterResponse:
            await stream.write(H1Empty200CloseResponse)
          else:
            await stream.write(H1Empty200KeepAliveResponse)
        else:
          responseBuffer.setLen(0)
          responseBuffer.add "HTTP/1.1 200 OK\r\nContent-Length: "
          responseBuffer.addInt(resp.body.len)
          if shouldCloseAfterResponse:
            responseBuffer.add "\r\nConnection: close\r\n\r\n"
          else:
            responseBuffer.add "\r\n\r\n"
          await stream.writevBorrowed(
            addr responseBuffer[0], responseBuffer.len,
            resp.body.data, resp.body.len)
      else:
        if isHeadRequest:
          let hint = headBodyLengthHint(resp)
          await writeResponseBuffered(stream, resp, responseBuffer,
            sendBody = false, bodyLengthHint = hint)
        else:
          await writeResponseBuffered(stream, resp, responseBuffer)
    except CatchableError:
      writeFailed = true
    if writeFailed:
      break

    if shouldCloseAfterResponse:
      canCloseImmediately = true
      break

    # Respect explicit close from response.
    if headersHaveToken(resp.headers, "connection", "close"):
      canCloseImmediately = true
      break

  if canCloseImmediately and stream of TcpStream:
    TcpStream(stream).closeImmediately()
  else:
    stream.close()
