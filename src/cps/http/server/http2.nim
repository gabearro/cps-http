## HTTP/2 Server Implementation
##
## Server-side HTTP/2 frame processing, stream dispatch, strict request parsing,
## and connection-scoped serialized writes.

import std/[strutils, tables, deques]
import cps/runtime
import cps/transform
import cps/eventloop
import cps/concurrency/taskgroup
import cps/io/streams
import cps/io/buffered
import ../shared/hpack
import ../shared/http2
import ./types
import ../shared/http2_stream_adapter

type
  SerializedWritePayload = ref object
    data: string

  OutboundWrite = object
    frame: Http2Frame
    serialized: SerializedWritePayload
    completion: CpsVoidFuture

  PeerStreamRange = object
    first: uint32
    last: uint32

  Http2ServerStream* = ref object
    id*: uint32
    state*: Http2StreamState
    requestHeaders*: seq[(string, string)]
    requestBody*: seq[byte]
    endStream*: bool
    adapter*: Http2StreamAdapter
    remoteWindowSize*: int
    bodyBytesRead*: int
    headerBlock*: seq[byte]
    headerBlockEndStream*: bool
    headersComplete*: bool
    dispatched*: bool
    windowWaiters*: seq[CpsVoidFuture]
    expectedContentLength*: int64

  Http2ServerConnection* = ref object
    stream*: AsyncStream
    reader*: BufferedReader
    encoder*: HpackEncoder
    decoder*: HpackDecoder
    headerEncodeScratch: seq[byte]
    streams*: Table[uint32, Http2ServerStream]
    streamPool: seq[Http2ServerStream]
    localWindowSize*: int
    remoteWindowSize*: int
    remoteSettings*: Table[uint16, uint32]
    config*: HttpServerConfig
    handler*: HttpHandler
    running*: bool
    lastStreamId*: uint32
    maxConcurrentStreams*: int
    streamGroup*: TaskGroup
    peerInitialWindowSize*: int
    peerMaxFrameSize*: int
    acceptingNewStreams*: bool
    continuationStreamId*: uint32
    outboundQueue*: Deque[OutboundWrite]
    writerRunning*: bool
    writerPayload: string
    writerCompletions: seq[CpsVoidFuture]
    writerWrite: CpsVoidFuture
    writerError*: ref CatchableError
    connectionWindowWaiters*: seq[CpsVoidFuture]
    shutdownFlag*: ptr bool
    goAwaySent*: bool
    remoteAddr*: string
    seenPeerStreamRanges: seq[PeerStreamRange]

const
  H2ErrNoError = 0'u32
  H2ErrProtocolError = 1'u32
  H2ErrInternalError = 2'u32
  H2ErrFlowControlError = 3'u32
  H2ErrSettingsTimeout = 4'u32
  H2ErrStreamClosed = 5'u32
  H2ErrFrameSizeError = 6'u32
  H2ErrRefusedStream = 7'u32
  H2ErrCancel = 8'u32
  H2ErrCompressionError = 9'u32
  H2ErrEnhanceYourCalm = 11'u32
  MaxPooledStreams = 64
  MaxRetainedRequestBodyBytes = 64 * 1024
  MaxRetainedRequestHeaders = 64
  MaxRetainedHeaderEncodeBytes = 64 * 1024
  MaxWriterBatchBytes = 16 * 1024
  MaxWriterBatchEntries = 128

proc wakeWaiters(waiters: var seq[CpsVoidFuture]) =
  for i in 0 ..< waiters.len:
    let fut = waiters[i]
    if not fut.isNil and not fut.finished:
      fut.complete()
  waiters.setLen(0)

proc failWaiters(waiters: var seq[CpsVoidFuture], err: ref CatchableError) =
  for i in 0 ..< waiters.len:
    let fut = waiters[i]
    if not fut.isNil and not fut.finished:
      fut.fail(err)
  waiters.setLen(0)

proc newHttp2ServerConnection*(s: AsyncStream, config: HttpServerConfig,
                               handler: HttpHandler,
                               shutdownFlag: ptr bool = nil,
                               remoteAddr: string = ""): Http2ServerConnection =
  ## Create a new http2 server connection.
  let reader = newBufferedReader(s)
  Http2ServerConnection(
    stream: s,
    reader: reader,
    encoder: initHpackEncoder(),
    decoder: initHpackDecoder(),
    headerEncodeScratch: @[],
    streams: initTable[uint32, Http2ServerStream](),
    streamPool: @[],
    localWindowSize: DefaultWindowSize,
    remoteWindowSize: DefaultWindowSize,
    remoteSettings: initTable[uint16, uint32](),
    config: config,
    handler: handler,
    running: true,
    lastStreamId: 0,
    maxConcurrentStreams: 100,
    streamGroup: newTaskGroup(epCollectAll),
    peerInitialWindowSize: DefaultWindowSize,
    peerMaxFrameSize: DefaultMaxFrameSize,
    acceptingNewStreams: true,
    continuationStreamId: 0,
    outboundQueue: initDeque[OutboundWrite](),
    writerRunning: false,
    writerPayload: newStringOfCap(MaxWriterBatchBytes),
    writerCompletions: newSeqOfCap[CpsVoidFuture](MaxWriterBatchEntries),
    writerWrite: nil,
    writerError: nil,
    connectionWindowWaiters: @[],
    shutdownFlag: shutdownFlag,
    goAwaySent: false,
    remoteAddr: remoteAddr,
    seenPeerStreamRanges: @[]
  )

proc failPendingOutbound(conn: Http2ServerConnection, err: ref CatchableError) =
  while conn.outboundQueue.len > 0:
    let pending = conn.outboundQueue.popFirst()
    if not pending.completion.finished:
      pending.completion.fail(err)

proc failWriterCompletions(conn: Http2ServerConnection,
                           err: ref CatchableError) =
  for fut in conn.writerCompletions:
    if not fut.finished:
      fut.fail(err)
  conn.writerCompletions.setLen(0)
  conn.writerPayload.setLen(0)

proc completeWriterCompletions(conn: Http2ServerConnection) =
  for fut in conn.writerCompletions:
    if not fut.finished:
      fut.complete()
  conn.writerCompletions.setLen(0)
  conn.writerPayload.setLen(0)

proc pumpWriter(conn: Http2ServerConnection)

proc finishWriterWrite(conn: Http2ServerConnection) =
  let writeFut = conn.writerWrite
  conn.writerWrite = nil
  if writeFut.isNil:
    return
  if writeFut.hasError:
    let err = writeFut.getError()
    conn.writerError = err
    conn.running = false
    conn.failWriterCompletions(err)
    conn.failPendingOutbound(err)
    conn.writerRunning = false
    return
  conn.completeWriterCompletions()
  conn.pumpWriter()

proc pumpWriter(conn: Http2ServerConnection) =
  if not conn.running:
    conn.writerRunning = false
    return

  while conn.outboundQueue.len > 0:
    conn.writerPayload.setLen(0)
    conn.writerCompletions.setLen(0)

    while conn.outboundQueue.len > 0 and
        conn.writerCompletions.len < MaxWriterBatchEntries:
      let next = conn.outboundQueue.peekFirst()
      let nextLen =
        if not next.serialized.isNil: next.serialized.data.len
        else: 9 + next.frame.payload.len
      if conn.writerPayload.len > 0 and
          conn.writerPayload.len + nextLen > MaxWriterBatchBytes:
        break

      var pending = conn.outboundQueue.popFirst()
      if not pending.serialized.isNil:
        conn.writerPayload.add(pending.serialized.data)
      else:
        conn.writerPayload.appendSerializedFrame(pending.frame)
      conn.writerCompletions.add(move(pending.completion))

    let writeFut = conn.stream.write(conn.writerPayload)
    if writeFut.finished:
      if writeFut.hasError:
        let err = writeFut.getError()
        conn.writerError = err
        conn.running = false
        conn.failWriterCompletions(err)
        conn.failPendingOutbound(err)
        conn.writerRunning = false
        return
      conn.completeWriterCompletions()
      continue

    conn.writerWrite = writeFut
    writeFut.addCallback(proc() =
      conn.finishWriterWrite()
    )
    return

  conn.writerRunning = false

proc scheduleWriter(conn: Http2ServerConnection) =
  if conn.writerRunning:
    return
  conn.writerRunning = true
  if deferCurrentWorker(proc() =
    if not deferCurrentWorker(proc() = conn.pumpWriter()):
      getEventLoop().scheduleCallback(proc() = conn.pumpWriter())
  ):
    return
  getEventLoop().scheduleCallback(proc() = conn.pumpWriter())

proc enqueueWrite(conn: Http2ServerConnection, data: sink string): CpsVoidFuture =
  let fut = newCpsVoidFuture()
  if not conn.running:
    fut.fail(newException(system.IOError, "HTTP/2 connection is closed"))
    return fut
  if not conn.writerError.isNil:
    fut.fail(conn.writerError)
    return fut

  conn.outboundQueue.addLast(OutboundWrite(
    serialized: SerializedWritePayload(data: data),
    completion: fut
  ))

  conn.scheduleWriter()

  return fut

proc enqueueFrame(conn: Http2ServerConnection, frame: Http2Frame): CpsVoidFuture =
  let fut = newCpsVoidFuture()
  if not conn.running:
    fut.fail(newException(system.IOError, "HTTP/2 connection is closed"))
    return fut
  if not conn.writerError.isNil:
    fut.fail(conn.writerError)
    return fut

  conn.outboundQueue.addLast(OutboundWrite(
    frame: frame,
    completion: fut
  ))

  conn.scheduleWriter()

  fut

proc sendFrame*(conn: Http2ServerConnection,
                frame: Http2Frame): CpsVoidFuture {.inline.} =
  ## Send frame through the active transport.
  enqueueFrame(conn, frame)

proc sendRstStream(conn: Http2ServerConnection, streamId: uint32,
                   errorCode: uint32): CpsVoidFuture {.cps.} =
  let payload = @[
    byte((errorCode shr 24) and 0xFF),
    byte((errorCode shr 16) and 0xFF),
    byte((errorCode shr 8) and 0xFF),
    byte(errorCode and 0xFF)
  ]
  await sendFrame(conn, Http2Frame(
    frameType: FrameRstStream,
    flags: 0,
    streamId: streamId,
    payload: payload
  ))

## Send go away through the active transport.
proc sendGoAway*(conn: Http2ServerConnection, errorCode: uint32,
                 lastStreamId: uint32 = 0'u32): CpsVoidFuture {.cps.} =
  if conn.goAwaySent:
    return
  conn.goAwaySent = true

  let lastId = if lastStreamId == 0'u32: conn.lastStreamId else: lastStreamId
  var payload: seq[byte]
  payload.add byte((lastId shr 24) and 0x7F)
  payload.add byte((lastId shr 16) and 0xFF)
  payload.add byte((lastId shr 8) and 0xFF)
  payload.add byte(lastId and 0xFF)
  payload.add byte((errorCode shr 24) and 0xFF)
  payload.add byte((errorCode shr 16) and 0xFF)
  payload.add byte((errorCode shr 8) and 0xFF)
  payload.add byte(errorCode and 0xFF)

  await sendFrame(conn, Http2Frame(
    frameType: FrameGoAway,
    flags: 0,
    streamId: 0,
    payload: payload
  ))

proc failConnection(conn: Http2ServerConnection, errorCode: uint32): CpsVoidFuture {.cps.} =
  if conn.running and not conn.goAwaySent:
    try:
      await conn.sendGoAway(errorCode)
    except CatchableError:
      discard
  conn.running = false

proc wakeConnectionWaiters(conn: Http2ServerConnection) =
  wakeWaiters(conn.connectionWindowWaiters)

proc failConnectionWaiters(conn: Http2ServerConnection, err: ref CatchableError) =
  failWaiters(conn.connectionWindowWaiters, err)

proc applyPeerInitialWindowSize(conn: Http2ServerConnection,
                                newInitialWindowSize: int): bool =
  let delta = newInitialWindowSize - conn.peerInitialWindowSize

  if delta == 0:
    return true

  for sid, streamRef in conn.streams:
    let newWindow = streamRef.remoteWindowSize + delta
    if newWindow > 0x7FFF_FFFF:
      return false

  conn.peerInitialWindowSize = newInitialWindowSize
  for sid, streamRef in conn.streams:
    streamRef.remoteWindowSize += delta
    wakeWaiters(streamRef.windowWaiters)

  true

proc acquireStream(conn: Http2ServerConnection,
                   streamId: uint32): Http2ServerStream {.inline.} =
  ## Stream IDs are short-lived but their small header/body vectors are useful
  ## again on the same connection. Keep ownership reactor-local and recycle a
  ## bounded number of stream objects to avoid allocator traffic.
  if conn.streamPool.len > 0:
    result = conn.streamPool.pop()
  else:
    result = Http2ServerStream()

  result.id = streamId
  result.state = ssOpen
  result.requestHeaders.setLen(0)
  result.requestBody.setLen(0)
  result.endStream = false
  result.adapter = nil
  result.remoteWindowSize = conn.peerInitialWindowSize
  result.bodyBytesRead = 0
  result.headerBlock.setLen(0)
  result.headerBlockEndStream = false
  result.headersComplete = false
  result.dispatched = false
  result.windowWaiters.setLen(0)
  result.expectedContentLength = -1

proc recycleStream(conn: Http2ServerConnection,
                   s: Http2ServerStream) {.inline.} =
  s.adapter = nil
  if s.requestHeaders.len > MaxRetainedRequestHeaders:
    s.requestHeaders = @[]
  else:
    s.requestHeaders.setLen(0)
  if s.requestBody.len > MaxRetainedRequestBodyBytes:
    s.requestBody = @[]
  else:
    s.requestBody.setLen(0)
  s.headerBlock.setLen(0)
  s.windowWaiters.setLen(0)
  if conn.streamPool.len < min(conn.maxConcurrentStreams, MaxPooledStreams):
    conn.streamPool.add s

proc closeStream(conn: Http2ServerConnection, streamId: uint32,
                 err: ref CatchableError = nil) =
  if streamId notin conn.streams:
    return
  let s = conn.streams[streamId]
  s.state = ssClosed
  if s.adapter != nil:
    s.adapter.feedEof()
  if err.isNil:
    wakeWaiters(s.windowWaiters)
  else:
    failWaiters(s.windowWaiters, err)
  conn.streams.del(streamId)
  conn.recycleStream(s)

proc sendRstAndClose(conn: Http2ServerConnection, streamId: uint32,
                     errorCode: uint32): CpsVoidFuture {.cps.} =
  ## Preserve wire ordering on exceptional paths without forcing the ordinary
  ## successful HEADERS path through a CPS state machine.
  await sendRstStream(conn, streamId, errorCode)
  conn.closeStream(streamId)

proc peerStreamWasOpened(conn: Http2ServerConnection,
                         streamId: uint32): bool {.inline.} =
  var low = 0
  var high = conn.seenPeerStreamRanges.len
  while low < high:
    let mid = low + (high - low) div 2
    let r = conn.seenPeerStreamRanges[mid]
    if streamId < r.first:
      high = mid
    elif streamId > r.last:
      low = mid + 1
    else:
      return true
  false

proc markPeerStreamSeen(conn: Http2ServerConnection, streamId: uint32) {.inline.} =
  ## Client stream IDs arrive in increasing order. Compress the overwhelmingly
  ## common contiguous sequence into one range instead of retaining a hash
  ## table entry for every completed request. Gaps remain exact protocol state.
  if conn.seenPeerStreamRanges.len > 0:
    let lastIdx = conn.seenPeerStreamRanges.high
    if conn.seenPeerStreamRanges[lastIdx].last + 2'u32 == streamId:
      conn.seenPeerStreamRanges[lastIdx].last = streamId
      return
  conn.seenPeerStreamRanges.add PeerStreamRange(first: streamId, last: streamId)

proc currentPeerMaxFrameSize(conn: Http2ServerConnection): int {.inline.} =
  if conn.peerMaxFrameSize < DefaultMaxFrameSize:
    return DefaultMaxFrameSize
  conn.peerMaxFrameSize

proc sendServerSettings*(conn: Http2ServerConnection): CpsVoidFuture {.cps.} =
  ## Send server settings through the active transport.
  var payload: seq[byte]
  let maxStreams = conn.maxConcurrentStreams.uint32
  payload.add byte((SettingsMaxConcurrentStreams shr 8) and 0xFF)
  payload.add byte(SettingsMaxConcurrentStreams and 0xFF)
  payload.add byte((maxStreams shr 24) and 0xFF)
  payload.add byte((maxStreams shr 16) and 0xFF)
  payload.add byte((maxStreams shr 8) and 0xFF)
  payload.add byte(maxStreams and 0xFF)

  let winSize = DefaultWindowSize.uint32
  payload.add byte((SettingsInitialWindowSize shr 8) and 0xFF)
  payload.add byte(SettingsInitialWindowSize and 0xFF)
  payload.add byte((winSize shr 24) and 0xFF)
  payload.add byte((winSize shr 16) and 0xFF)
  payload.add byte((winSize shr 8) and 0xFF)
  payload.add byte(winSize and 0xFF)

  let enableConnect = 1'u32
  payload.add byte((SettingsEnableConnectProtocol shr 8) and 0xFF)
  payload.add byte(SettingsEnableConnectProtocol and 0xFF)
  payload.add byte((enableConnect shr 24) and 0xFF)
  payload.add byte((enableConnect shr 16) and 0xFF)
  payload.add byte((enableConnect shr 8) and 0xFF)
  payload.add byte(enableConnect and 0xFF)

  await sendFrame(conn, Http2Frame(
    frameType: FrameSettings,
    flags: 0,
    streamId: 0,
    payload: payload
  ))

proc readConnectionPreface*(conn: Http2ServerConnection): CpsVoidFuture {.cps.} =
  ## Read and validate the HTTP/2 client connection preface.
  let preface = await conn.reader.readExact(ConnectionPreface.len)
  if preface != ConnectionPreface:
    raise newException(ValueError, "Invalid HTTP/2 connection preface")

proc recvServerFrame*(conn: Http2ServerConnection): CpsFuture[Http2Frame] {.cps.} =
  ## Receive server frame from the active transport.
  let headerStr = await conn.reader.readExact(9)
  if headerStr.len < 9:
    raise newException(system.IOError, "Short frame header")

  var frame = parseFrameHeader(headerStr)
  if frame.length.uint64 > 16_777_215'u64:
    raise newException(ValueError, "Invalid HTTP/2 frame length")
  if int(frame.length) > conn.localWindowSize and frame.frameType == FrameData:
    raise newException(ValueError, "Inbound DATA exceeds local flow-control window")
  if int(frame.length) > DefaultMaxFrameSize:
    raise newException(ValueError, "Inbound frame exceeds default max frame size")

  if frame.length > 0:
    let payloadStr = await conn.reader.readExact(int(frame.length))
    frame.payload = bytesFromString(payloadStr)
  else:
    frame.payload = @[]

  return frame

proc isPseudoHeader(name: string): bool {.inline.} =
  name.len > 0 and name[0] == ':'

proc isExtendedConnect(headers: seq[(string, string)]): bool =
  var meth = ""
  var proto = ""
  for i in 0 ..< headers.len:
    if headers[i][0] == ":method":
      meth = headers[i][1]
    elif headers[i][0] == ":protocol":
      proto = headers[i][1]
  meth == "CONNECT" and proto.len > 0

proc isConnectRequest(headers: seq[(string, string)]): bool =
  for i in 0 ..< headers.len:
    if headers[i][0] == ":method":
      return headers[i][1] == "CONNECT"
  false

proc validateH2RequestHeaders(conn: Http2ServerConnection,
                              headers: seq[(string, string)]): bool =
  proc parseContentLength(v: string, parsed: var int64): bool =
    if v.len == 0:
      return false
    for ch in v:
      if ch notin Digits:
        return false
    let n =
      try:
        parseBiggestInt(v)
      except ValueError:
        return false
    if n < 0 or n > int64(high(int)):
      return false
    parsed = int64(n)
    true

  proc isValidSchemeValue(value: string): bool =
    if value.len == 0:
      return false
    if value[0] notin Letters:
      return false
    for i in 1 ..< value.len:
      let c = value[i]
      if c notin (Letters + Digits + {'+', '-', '.'}):
        return false
    true

  proc isValidAuthorityValue(value: string): bool =
    if value.len == 0:
      return false
    for c in value:
      if c == ' ' or c == '\t':
        return false
      if ord(c) < 0x21 or ord(c) == 0x7F:
        return false
      if c in {'/', '?', '#'}:
        return false
    true

  proc isValidRequestPathValue(meth: string, value: string): bool =
    if value.len == 0:
      return false
    if value == "*":
      return meth == "OPTIONS"
    if value[0] != '/':
      return false
    for c in value:
      if ord(c) < 0x21 or ord(c) == 0x7F:
        return false
      if c == '#':
        return false
    true

  var sawRegular = false
  var seenPseudo = initTable[string, bool]()
  var headerBytes = 0

  if conn.config.maxHeaderCount > 0 and headers.len > conn.config.maxHeaderCount:
    return false

  var meth = ""
  var path = ""
  var scheme = ""
  var authority = ""
  var proto = ""
  var sawHostHeader = false
  var hostValue = ""
  var sawContentLength = false
  var contentLengthValue: int64 = -1

  for i in 0 ..< headers.len:
    let name = headers[i][0]
    let value = headers[i][1]

    headerBytes += name.len + value.len
    if conn.config.maxHeaderBytes > 0 and headerBytes > conn.config.maxHeaderBytes:
      return false

    if value.len > 0 and not isValidHeaderValue(value):
      return false

    if isPseudoHeader(name):
      if sawRegular:
        return false
      if name notin [":method", ":path", ":scheme", ":authority", ":protocol"]:
        return false
      if name in seenPseudo:
        return false
      seenPseudo[name] = true
      case name
      of ":method": meth = value
      of ":path": path = value
      of ":scheme": scheme = value
      of ":authority": authority = value
      of ":protocol": proto = value
      else: discard
    else:
      sawRegular = true
      if not isValidLowercaseHeaderName(name):
        return false
      let lname = name
      if lname in ["connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding"]:
        return false
      if lname == "te" and not eqCaseInsensitive(value, "trailers"):
        return false
      if lname == "host":
        if sawHostHeader:
          return false
        if not isValidAuthorityValue(value):
          return false
        sawHostHeader = true
        hostValue = value
      if lname == "content-length":
        var parsedLen = 0'i64
        if not parseContentLength(value, parsedLen):
          return false
        if sawContentLength and parsedLen != contentLengthValue:
          return false
        sawContentLength = true
        contentLengthValue = parsedLen

  if meth.len == 0:
    return false
  if not isValidHeaderName(meth):
    return false
  if scheme.len > 0 and not isValidSchemeValue(scheme):
    return false
  if authority.len > 0 and not isValidAuthorityValue(authority):
    return false
  if authority.len == 0 and ":authority" in seenPseudo:
    return false
  if proto.len > 0 and not isValidHeaderName(proto):
    return false
  if proto.len == 0 and ":protocol" in seenPseudo:
    return false
  if authority.len > 0 and sawHostHeader and
      not eqCaseInsensitive(authority, hostValue):
    return false

  if meth == "CONNECT":
    if proto.len > 0:
      if conn.remoteSettings.getOrDefault(SettingsEnableConnectProtocol, 0'u32) != 1'u32:
        return false
      # RFC 8441 extended CONNECT
      if scheme.len == 0 or path.len == 0 or authority.len == 0:
        return false
      if not isValidRequestPathValue(meth, path):
        return false
    else:
      if ":path" in seenPseudo or ":scheme" in seenPseudo:
        return false
      if authority.len == 0:
        return false
      if path.len > 0 or scheme.len > 0:
        return false
  else:
    if ":protocol" in seenPseudo:
      return false
    if path.len == 0 or scheme.len == 0:
      return false
    if not isValidRequestPathValue(meth, path):
      return false
    if authority.len == 0 and not sawHostHeader:
      return false

  true

proc validateH2TrailerHeaders(conn: Http2ServerConnection,
                              headers: seq[(string, string)]): bool =
  var headerBytes = 0

  if conn.config.maxHeaderCount > 0 and headers.len > conn.config.maxHeaderCount:
    return false

  for i in 0 ..< headers.len:
    let name = headers[i][0]
    let value = headers[i][1]

    if name.len == 0 or isPseudoHeader(name):
      return false
    if not isValidLowercaseHeaderName(name):
      return false
    if value.len > 0 and not isValidHeaderValue(value):
      return false

    let lname = name
    if lname in ["connection", "proxy-connection", "keep-alive", "upgrade",
                 "transfer-encoding", "te", "content-length"]:
      return false

    headerBytes += name.len + value.len
    if conn.config.maxHeaderBytes > 0 and headerBytes > conn.config.maxHeaderBytes:
      return false

  true

proc extractExpectedContentLength(headers: seq[(string, string)],
                                  expected: var int64): bool

proc validateH2ResponseHeaders(headers: seq[(string, string)]): bool =
  for i in 0 ..< headers.len:
    let name = headers[i][0]
    let value = headers[i][1]
    if name.len == 0:
      return false
    if name[0] == ':':
      return false

    if not isValidHeaderName(name):
      return false
    if not isValidHeaderValue(value):
      return false

    if eqCaseInsensitive(name, "connection") or
        eqCaseInsensitive(name, "proxy-connection") or
        eqCaseInsensitive(name, "keep-alive") or
        eqCaseInsensitive(name, "upgrade") or
        eqCaseInsensitive(name, "transfer-encoding") or
        eqCaseInsensitive(name, "te"):
      return false
  var expectedLen = -1'i64
  if not extractExpectedContentLength(headers, expectedLen):
    return false
  true

proc extractExpectedContentLength(headers: seq[(string, string)],
                                  expected: var int64): bool =
  var saw = false
  var parsedVal = -1'i64
  for i in 0 ..< headers.len:
    if not eqCaseInsensitive(headers[i][0], "content-length"):
      continue
    let value = headers[i][1]
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
    if n < 0 or n > int64(high(int)):
      return false
    let contentLen = int64(n)
    if saw and contentLen != parsedVal:
      return false
    saw = true
    parsedVal = contentLen
  if saw:
    expected = parsedVal
  else:
    expected = -1
  true

proc extractHeadersFragment(frame: Http2Frame, fragment: var seq[byte]): bool =
  var idx = 0
  var padLen = 0

  if (frame.flags and FlagPadded) != 0:
    if frame.payload.len < 1:
      return false
    padLen = int(frame.payload[0])
    idx = 1

  if (frame.flags and FlagPriority) != 0:
    if frame.payload.len < idx + 5:
      return false
    idx += 5

  if padLen > frame.payload.len - idx:
    return false

  let endIdx = frame.payload.len - padLen
  if endIdx < idx:
    return false

  if endIdx == idx:
    fragment = @[]
  else:
    fragment = frame.payload[idx ..< endIdx]
  true

proc extractPriorityDependency(frame: Http2Frame,
                               dependency: var uint32): bool =
  if frame.payload.len != 5:
    return false
  dependency = (uint32(frame.payload[0] and 0x7F) shl 24) or
               (uint32(frame.payload[1]) shl 16) or
               (uint32(frame.payload[2]) shl 8) or
               uint32(frame.payload[3])
  true

proc extractHeadersPriorityDependency(frame: Http2Frame,
                                      dependency: var uint32): bool =
  if frame.frameType != FrameHeaders or (frame.flags and FlagPriority) == 0:
    return false

  var idx = 0
  var padLen = 0
  if (frame.flags and FlagPadded) != 0:
    if frame.payload.len < 1:
      return false
    padLen = int(frame.payload[0])
    idx = 1

  if frame.payload.len < idx + 5:
    return false
  if padLen > frame.payload.len - (idx + 5):
    return false

  dependency = (uint32(frame.payload[idx] and 0x7F) shl 24) or
               (uint32(frame.payload[idx + 1]) shl 16) or
               (uint32(frame.payload[idx + 2]) shl 8) or
               uint32(frame.payload[idx + 3])
  true

proc extractDataPayload(frame: Http2Frame, payload: var seq[byte]): bool =
  if (frame.flags and FlagPadded) == 0:
    payload = frame.payload
    return true

  if frame.payload.len < 1:
    return false

  let padLen = int(frame.payload[0])
  if padLen >= frame.payload.len:
    return false

  let startIdx = 1
  let endIdx = frame.payload.len - padLen
  if endIdx < startIdx:
    return false

  if endIdx == startIdx:
    payload = @[]
  else:
    payload = frame.payload[startIdx ..< endIdx]
  true

proc serializeResponseHeaders(conn: Http2ServerConnection, streamId: uint32,
                              statusCode: int, headers: seq[(string, string)],
                              endStream: bool): string =
  if statusCode < 200 or statusCode > 999:
    raise newException(ValueError, "Invalid HTTP/2 response status code")
  if not validateH2ResponseHeaders(headers):
    raise newException(ValueError, "Invalid HTTP/2 response header")

  let encoded = addr conn.headerEncodeScratch
  encoded[].setLen(0)
  case statusCode
  of 200: encoded[].add 0x88'u8
  of 204: encoded[].add 0x89'u8
  of 206: encoded[].add 0x8A'u8
  of 304: encoded[].add 0x8B'u8
  of 400: encoded[].add 0x8C'u8
  of 404: encoded[].add 0x8D'u8
  of 500: encoded[].add 0x8E'u8
  else: conn.encoder.encodeHeaderInto(":status", $statusCode, encoded[])

  for i in 0 ..< headers.len:
    let name = headers[i][0]
    if isValidLowercaseHeaderName(name):
      conn.encoder.encodeHeaderInto(name, headers[i][1], encoded[])
    else:
      conn.encoder.encodeHeaderInto(name.toLowerAscii, headers[i][1], encoded[])

  let maxFrame = conn.currentPeerMaxFrameSize()
  let frameCount = max(1, (encoded[].len + maxFrame - 1) div maxFrame)
  result = newStringOfCap(encoded[].len + frameCount * 9)
  var offset = 0
  var first = true

  while offset < encoded[].len or (first and encoded[].len == 0):
    let remaining = encoded[].len - offset
    let chunkLen =
      if remaining <= 0: 0
      else: min(maxFrame, remaining)

    var flags: uint8 = 0
    if first and endStream:
      flags = flags or FlagEndStream
    if offset + chunkLen >= encoded[].len:
      flags = flags or FlagEndHeaders

    let ftype = if first: FrameHeaders else: FrameContinuation
    result.appendSerializedFrameSlice(
      ftype, flags, streamId, encoded[], offset, chunkLen
    )

    first = false
    offset += chunkLen
    if encoded[].len == 0:
      break

  if encoded[].len > MaxRetainedHeaderEncodeBytes:
    encoded[] = @[]

proc sendResponseHeaders*(conn: Http2ServerConnection, streamId: uint32,
                          statusCode: int, headers: seq[(string, string)],
                          endStream: bool): CpsVoidFuture =
  ## A header block may span HEADERS plus CONTINUATION frames, but it remains
  ## one ordered write.  Coalescing those frames avoids a TLS record/syscall
  ## per continuation without changing their HTTP/2 framing. Forwarding the
  ## writer's future also avoids an otherwise redundant CPS result future.
  try:
    var serialized = conn.serializeResponseHeaders(
      streamId, statusCode, headers, endStream
    )
    result = enqueueWrite(conn, move(serialized))
  except CatchableError as e:
    result = failedVoidFuture(e)

proc waitForSendWindow(conn: Http2ServerConnection,
                       streamId: uint32): CpsVoidFuture {.cps.} =
  while conn.running and streamId in conn.streams:
    let s = conn.streams[streamId]
    if conn.remoteWindowSize > 0 and s.remoteWindowSize > 0:
      return

    let waiter = newCpsVoidFuture()
    if conn.remoteWindowSize <= 0:
      conn.connectionWindowWaiters.add waiter
    if s.remoteWindowSize <= 0:
      s.windowWaiters.add waiter

    try:
      await waiter
    except CatchableError:
      return

proc sendResponseData*(conn: Http2ServerConnection, streamId: uint32,
                       data: seq[byte], endStream: bool): CpsVoidFuture {.cps.} =
  ## Send response data through the active transport.
  if streamId notin conn.streams:
    return

  if data.len == 0:
    if endStream:
      await sendFrame(conn, Http2Frame(
        frameType: FrameData,
        flags: FlagEndStream,
        streamId: streamId,
        payload: @[]
      ))
    return

  let maxFrame = conn.currentPeerMaxFrameSize()
  var offset = 0

  while offset < data.len and conn.running and streamId in conn.streams:
    await waitForSendWindow(conn, streamId)
    if streamId notin conn.streams or not conn.running:
      return

    let s = conn.streams[streamId]
    let remaining = data.len - offset
    let window = min(conn.remoteWindowSize, s.remoteWindowSize)
    let chunkLen = min(min(maxFrame, remaining), window)
    if chunkLen <= 0:
      continue

    conn.remoteWindowSize -= chunkLen
    s.remoteWindowSize -= chunkLen

    let isLast = (offset + chunkLen >= data.len) and endStream
    let chunk = data[offset ..< offset + chunkLen]

    await sendFrame(conn, Http2Frame(
      frameType: FrameData,
      flags: (if isLast: FlagEndStream else: 0'u8),
      streamId: streamId,
      payload: chunk
    ))
    offset += chunkLen

proc trySendBufferedResponse(conn: Http2ServerConnection,
                             streamId: uint32,
                             statusCode: int,
                             headers: seq[(string, string)],
                             data: seq[byte]): CpsFuture[bool] {.cps.} =
  ## A buffered response whose body already fits the advertised send windows
  ## can be framed atomically.  HEADERS and DATA keep their normal HTTP/2
  ## boundaries, while sharing one ordered TLS write and one completion.
  if streamId notin conn.streams or not conn.running:
    return true
  let s = conn.streams[streamId]
  if data.len > conn.remoteWindowSize or data.len > s.remoteWindowSize:
    return false

  var serialized = conn.serializeResponseHeaders(
    streamId, statusCode, headers, false
  )
  let maxFrame = conn.currentPeerMaxFrameSize()
  var offset = 0
  while offset < data.len:
    let chunkLen = min(maxFrame, data.len - offset)
    let isLast = offset + chunkLen >= data.len
    serialized.appendSerializedFrameSlice(
      FrameData,
      (if isLast: FlagEndStream else: 0'u8),
      streamId,
      data,
      offset,
      chunkLen
    )
    offset += chunkLen

  conn.remoteWindowSize -= data.len
  s.remoteWindowSize -= data.len
  await enqueueWrite(conn, serialized)
  return true

proc statusProhibitsBody(statusCode: int): bool {.inline.} =
  (statusCode >= 100 and statusCode < 200) or statusCode == 204 or
    statusCode == 205 or statusCode == 304

proc buildHttpRequest(s: Http2ServerStream,
                      conn: Http2ServerConnection): HttpRequest =
  var req = HttpRequest(
    streamId: s.id,
    context: nil,
    remoteAddr: conn.remoteAddr,
    maxWsFrameBytes: conn.config.maxWsFrameBytes,
    maxWsMessageBytes: conn.config.maxWsMessageBytes
  )

  for i in 0 ..< s.requestHeaders.len:
    let k = s.requestHeaders[i][0]
    let v = s.requestHeaders[i][1]
    case k
    of ":method": req.meth = v
    of ":path": req.path = v
    of ":authority": req.authority = v
    of ":scheme": req.scheme = v
    of ":protocol": req.headers.add (k, v)
    else: req.headers.add (k, v)

  if req.authority.len == 0:
    for i in 0 ..< req.headers.len:
      if eqCaseInsensitive(req.headers[i][0], "host"):
        req.authority = req.headers[i][1]
        break

  req.httpVersion = "HTTP/2"
  if s.requestBody.len > 0:
    req.body = newString(s.requestBody.len)
    for i in 0 ..< s.requestBody.len:
      req.body[i] = char(s.requestBody[i])

  if conn.config.trustedForwardedHeaders and
      isTrustedProxyAddress(conn.remoteAddr, conn.config.trustedProxyCidrs):
    ensureContext(req)
    req.context["trusted_proxy"] = "1"

  if s.adapter == nil:
    let sendHeadersCb: AdapterSendHeadersProc = proc(streamId: uint32, statusCode: int,
                                                     headers: seq[(string, string)]): CpsVoidFuture {.closure.} =
      sendResponseHeaders(conn, streamId, statusCode, headers, false)

    let sendDataCb: AdapterSendDataProc = proc(streamId: uint32, data: string): CpsVoidFuture {.closure.} =
      var bytes = newSeq[byte](data.len)
      for i in 0 ..< data.len:
        bytes[i] = byte(data[i])
      sendResponseData(conn, streamId, bytes, false)

    s.adapter = newHttp2StreamAdapter(s.id, sendHeadersCb, sendDataCb)
    if s.endStream:
      s.adapter.feedEof()

  req.stream = s.adapter.AsyncStream
  # HTTP/2 request bodies are fed through the stream adapter. A buffered
  # reader is only needed by WebSocket framing and is created lazily there.
  req.reader = nil
  return req

proc dispatchHttp2Handler*(conn: Http2ServerConnection, streamId: uint32,
                           req: HttpRequest): CpsVoidFuture {.cps.} =
  ## Dispatch an HTTP/2 request to its application handler.
  var resp: HttpResponseBuilder
  try:
    resp = await conn.handler(req)
  except CatchableError:
    resp = newResponse(500, "Internal Server Error")

  if streamId notin conn.streams:
    return

  if resp.control == rcHandled or resp.statusCode == 0:
    let s = conn.streams[streamId]
    if s.adapter != nil and s.adapter.hasSentResponseHeaders():
      await sendResponseData(conn, streamId, @[], true)
    else:
      await sendResponseHeaders(conn, streamId, 204, @[], true)
    conn.closeStream(streamId)
    return

  let streamRef = conn.streams[streamId]
  if streamRef.adapter != nil and streamRef.adapter.hasSentResponseHeaders():
    # The handler already started streaming a response on this stream.
    # Suppress any additional response builder emission to avoid duplicate
    # final HEADERS blocks (:status pseudo-header) on the same stream.
    await sendResponseData(conn, streamId, @[], true)
    conn.closeStream(streamId)
    return

  if resp.statusCode < 200 or resp.statusCode > 999 or
      not validateH2ResponseHeaders(resp.headers):
    resp = newResponse(500, "Internal Server Error")

  var respHeaders: seq[(string, string)]
  for i in 0 ..< resp.headers.len:
    respHeaders.add resp.headers[i]

  let suppressBody = req.meth == "HEAD" or statusProhibitsBody(resp.statusCode)

  var expectedRespLen = -1'i64
  if not extractExpectedContentLength(respHeaders, expectedRespLen) or
      (expectedRespLen >= 0 and not suppressBody and expectedRespLen != int64(resp.body.len)):
    resp = newResponse(500, "Internal Server Error")
    respHeaders.setLen(0)
    for i in 0 ..< resp.headers.len:
      respHeaders.add resp.headers[i]
    expectedRespLen = -1
    discard extractExpectedContentLength(respHeaders, expectedRespLen)

  if expectedRespLen < 0 and resp.body.len > 0 and
      (req.meth == "HEAD" or not statusProhibitsBody(resp.statusCode)):
    respHeaders.add ("content-length", $resp.body.len)

  if suppressBody or resp.body.len == 0:
    await sendResponseHeaders(conn, streamId, resp.statusCode, respHeaders, true)
  else:
    var bodyBytes = newSeq[byte](resp.body.len)
    for i in 0 ..< resp.body.len:
      bodyBytes[i] = byte(resp.body[i])
    let sentBuffered = await trySendBufferedResponse(
      conn, streamId, resp.statusCode, respHeaders, bodyBytes
    )
    if not sentBuffered:
      await sendResponseHeaders(conn, streamId, resp.statusCode, respHeaders, false)
      await sendResponseData(conn, streamId, bodyBytes, true)

  conn.closeStream(streamId)

proc maybeDispatchStream(conn: Http2ServerConnection,
                         s: Http2ServerStream) =
  if s.dispatched or not s.headersComplete:
    return

  if isConnectRequest(s.requestHeaders) or s.endStream:
    s.dispatched = true
    let req = buildHttpRequest(s, conn)
    conn.streamGroup.spawn(dispatchHttp2Handler(conn, s.id, req))

proc completeHeaderBlock(conn: Http2ServerConnection,
                         streamId: uint32): CpsVoidFuture =
  if streamId notin conn.streams:
    return cachedCompletedVoidFuture()
  let s = conn.streams[streamId]

  let isTrailerBlock = s.headersComplete
  var decoded: seq[(string, string)]
  var decodeFailed = false
  try:
    if isTrailerBlock:
      conn.decoder.decodeInto(s.headerBlock, decoded)
    else:
      conn.decoder.decodeInto(s.headerBlock, s.requestHeaders)
  except CatchableError:
    decodeFailed = true

  if decodeFailed:
    return failConnection(conn, H2ErrCompressionError)

  if isTrailerBlock:
    if conn.config.maxHeaderCount > 0 and
        s.requestHeaders.len + decoded.len > conn.config.maxHeaderCount:
      return sendRstAndClose(conn, streamId, H2ErrProtocolError)

    if conn.config.maxHeaderBytes > 0:
      var totalHeaderBytes = 0
      for i in 0 ..< s.requestHeaders.len:
        totalHeaderBytes += s.requestHeaders[i][0].len + s.requestHeaders[i][1].len
      for i in 0 ..< decoded.len:
        totalHeaderBytes += decoded[i][0].len + decoded[i][1].len
      if totalHeaderBytes > conn.config.maxHeaderBytes:
        return sendRstAndClose(conn, streamId, H2ErrProtocolError)

    if not validateH2TrailerHeaders(conn, decoded):
      return sendRstAndClose(conn, streamId, H2ErrProtocolError)
    s.requestHeaders.add(decoded)
  else:
    if not validateH2RequestHeaders(conn, s.requestHeaders):
      return sendRstAndClose(conn, streamId, H2ErrProtocolError)
    var expectedLen = -1'i64
    if not extractExpectedContentLength(s.requestHeaders, expectedLen):
      return sendRstAndClose(conn, streamId, H2ErrProtocolError)
    s.expectedContentLength = expectedLen
    s.headersComplete = true
  s.headerBlock.setLen(0)

  if s.headerBlockEndStream:
    if s.expectedContentLength >= 0 and int64(s.bodyBytesRead) != s.expectedContentLength:
      return sendRstAndClose(conn, streamId, H2ErrProtocolError)
    s.endStream = true
    s.state = ssHalfClosedRemote
    if s.adapter != nil:
      s.adapter.feedEof()

  maybeDispatchStream(conn, s)
  cachedCompletedVoidFuture()

proc processHeadersFrame(conn: Http2ServerConnection,
                         frame: Http2Frame): CpsVoidFuture =
  let streamId = frame.streamId
  if streamId == 0 or streamId mod 2 == 0:
    return failConnection(conn, H2ErrProtocolError)

  let streamExists = streamId in conn.streams
  if not streamExists:
    if streamId <= conn.lastStreamId:
      return failConnection(conn, H2ErrProtocolError)
    if not conn.acceptingNewStreams and streamId > conn.lastStreamId:
      conn.markPeerStreamSeen(streamId)
      return sendRstStream(conn, streamId, H2ErrRefusedStream)
    conn.lastStreamId = streamId

  var s: Http2ServerStream
  if streamExists:
    s = conn.streams[streamId]
    if s.headersComplete and s.endStream:
      return sendRstAndClose(conn, streamId, H2ErrStreamClosed)
    if s.headersComplete and (frame.flags and FlagEndStream) == 0:
      return sendRstAndClose(conn, streamId, H2ErrProtocolError)
  else:
    if conn.maxConcurrentStreams > 0 and conn.streams.len >= conn.maxConcurrentStreams:
      conn.markPeerStreamSeen(streamId)
      return sendRstStream(conn, streamId, H2ErrRefusedStream)
    s = conn.acquireStream(streamId)
    conn.streams[streamId] = s
    conn.markPeerStreamSeen(streamId)

  if (frame.flags and FlagPriority) != 0:
    var dependency = 0'u32
    if not extractHeadersPriorityDependency(frame, dependency):
      return failConnection(conn, H2ErrProtocolError)
    if dependency == streamId:
      return sendRstAndClose(conn, streamId, H2ErrProtocolError)

  var fragment: seq[byte]
  if not extractHeadersFragment(frame, fragment):
    return failConnection(conn, H2ErrProtocolError)

  s.headerBlock.add(fragment)
  if (frame.flags and FlagEndStream) != 0:
    s.headerBlockEndStream = true

  if (frame.flags and FlagEndHeaders) == 0:
    conn.continuationStreamId = streamId
    return cachedCompletedVoidFuture()
  else:
    return completeHeaderBlock(conn, streamId)

proc processContinuationFrame(conn: Http2ServerConnection,
                              frame: Http2Frame): CpsVoidFuture =
  if conn.continuationStreamId == 0 or frame.streamId != conn.continuationStreamId:
    return failConnection(conn, H2ErrProtocolError)

  if frame.streamId notin conn.streams:
    return failConnection(conn, H2ErrProtocolError)

  let s = conn.streams[frame.streamId]
  s.headerBlock.add(frame.payload)

  if (frame.flags and FlagEndHeaders) != 0:
    conn.continuationStreamId = 0
    return completeHeaderBlock(conn, frame.streamId)
  cachedCompletedVoidFuture()

proc processServerFrameSlow(conn: Http2ServerConnection,
                            frame: Http2Frame): CpsVoidFuture {.cps.} =
  ## Apply less common HTTP/2 frame types through the general async path.
  if conn.continuationStreamId != 0 and
      (frame.frameType != FrameContinuation or frame.streamId != conn.continuationStreamId):
    await failConnection(conn, H2ErrProtocolError)
    return

  case frame.frameType
  of FrameSettings:
    if frame.streamId != 0:
      await failConnection(conn, H2ErrProtocolError)
      return

    if (frame.flags and FlagAck) != 0:
      if frame.payload.len != 0:
        await failConnection(conn, H2ErrFrameSizeError)
      return

    if frame.payload.len mod 6 != 0:
      await failConnection(conn, H2ErrFrameSizeError)
      return

    var offset = 0
    while offset + 5 < frame.payload.len:
      let id = (uint16(frame.payload[offset]) shl 8) or uint16(frame.payload[offset + 1])
      let value = (uint32(frame.payload[offset + 2]) shl 24) or
                  (uint32(frame.payload[offset + 3]) shl 16) or
                  (uint32(frame.payload[offset + 4]) shl 8) or
                  uint32(frame.payload[offset + 5])

      case id
      of SettingsInitialWindowSize:
        if value > 0x7FFF_FFFF'u32:
          await failConnection(conn, H2ErrFlowControlError)
          return
        if not applyPeerInitialWindowSize(conn, int(value)):
          await failConnection(conn, H2ErrFlowControlError)
          return
      of SettingsEnablePush:
        if value > 1'u32:
          await failConnection(conn, H2ErrProtocolError)
          return
      of SettingsEnableConnectProtocol:
        if value > 1'u32:
          await failConnection(conn, H2ErrProtocolError)
          return
      of SettingsMaxFrameSize:
        if value < DefaultMaxFrameSize.uint32 or value > 16_777_215'u32:
          await failConnection(conn, H2ErrProtocolError)
          return
        conn.peerMaxFrameSize = int(value)
      else:
        discard

      conn.remoteSettings[id] = value
      offset += 6

    await sendFrame(conn, Http2Frame(
      frameType: FrameSettings,
      flags: FlagAck,
      streamId: 0,
      payload: @[]
    ))

  of FrameHeaders:
    await processHeadersFrame(conn, frame)

  of FrameContinuation:
    await processContinuationFrame(conn, frame)

  of FrameData:
    let streamId = frame.streamId
    if streamId == 0:
      await failConnection(conn, H2ErrProtocolError)
      return

    if streamId notin conn.streams:
      if (streamId mod 2) == 0 or streamId > conn.lastStreamId:
        await failConnection(conn, H2ErrProtocolError)
      elif not conn.peerStreamWasOpened(streamId):
        await failConnection(conn, H2ErrProtocolError)
      else:
        await sendRstStream(conn, streamId, H2ErrStreamClosed)
      return

    let s = conn.streams[streamId]
    if not s.headersComplete:
      await sendRstStream(conn, streamId, H2ErrProtocolError)
      conn.closeStream(streamId)
      return
    if s.endStream:
      await sendRstStream(conn, streamId, H2ErrStreamClosed)
      conn.closeStream(streamId)
      return

    var dataPayload: seq[byte]
    if not extractDataPayload(frame, dataPayload):
      await failConnection(conn, H2ErrProtocolError)
      return

    let flowControlledLen = frame.payload.len
    if flowControlledLen > 0:
      conn.localWindowSize -= frame.payload.len
      await sendFrame(conn, Http2Frame(
        frameType: FrameWindowUpdate,
        flags: 0,
        streamId: 0,
        payload: @[
          byte((uint32(flowControlledLen) shr 24) and 0x7F),
          byte((uint32(flowControlledLen) shr 16) and 0xFF),
          byte((uint32(flowControlledLen) shr 8) and 0xFF),
          byte(uint32(flowControlledLen) and 0xFF)
        ]
      ))
      await sendFrame(conn, Http2Frame(
        frameType: FrameWindowUpdate,
        flags: 0,
        streamId: streamId,
        payload: @[
          byte((uint32(flowControlledLen) shr 24) and 0x7F),
          byte((uint32(flowControlledLen) shr 16) and 0xFF),
          byte((uint32(flowControlledLen) shr 8) and 0xFF),
          byte(uint32(flowControlledLen) and 0xFF)
        ]
      ))
      conn.localWindowSize += flowControlledLen

    if dataPayload.len > 0:
      s.bodyBytesRead += dataPayload.len
      if conn.config.maxRequestBodySize > 0 and
          s.bodyBytesRead > conn.config.maxRequestBodySize:
        await sendRstStream(conn, streamId, H2ErrCancel)
        conn.closeStream(streamId)
        return
      if s.expectedContentLength >= 0 and
          int64(s.bodyBytesRead) > s.expectedContentLength:
        await sendRstStream(conn, streamId, H2ErrProtocolError)
        conn.closeStream(streamId)
        return

    if s.adapter != nil:
      if dataPayload.len > 0:
        var dataStr = newString(dataPayload.len)
        for i in 0 ..< dataPayload.len:
          dataStr[i] = char(dataPayload[i])
        s.adapter.feedData(dataStr)
    else:
      if dataPayload.len > 0:
        s.requestBody.add dataPayload

    if (frame.flags and FlagEndStream) != 0:
      if s.expectedContentLength >= 0 and int64(s.bodyBytesRead) != s.expectedContentLength:
        await sendRstStream(conn, streamId, H2ErrProtocolError)
        conn.closeStream(streamId)
        return
      s.endStream = true
      s.state = ssHalfClosedRemote
      if s.adapter != nil:
        s.adapter.feedEof()
      maybeDispatchStream(conn, s)

  of FrameWindowUpdate:
    if frame.payload.len != 4:
      await failConnection(conn, H2ErrFrameSizeError)
      return

    let increment = (uint32(frame.payload[0] and 0x7F) shl 24) or
                    (uint32(frame.payload[1]) shl 16) or
                    (uint32(frame.payload[2]) shl 8) or
                    uint32(frame.payload[3])
    if increment == 0:
      if frame.streamId == 0:
        await failConnection(conn, H2ErrProtocolError)
      elif frame.streamId in conn.streams:
        await sendRstStream(conn, frame.streamId, H2ErrProtocolError)
        conn.closeStream(frame.streamId)
      elif (frame.streamId mod 2) == 0 or frame.streamId > conn.lastStreamId:
        await failConnection(conn, H2ErrProtocolError)
      elif not conn.peerStreamWasOpened(frame.streamId):
        await failConnection(conn, H2ErrProtocolError)
      return

    if frame.streamId == 0:
      let newWindow = conn.remoteWindowSize + int(increment)
      if newWindow > 0x7FFF_FFFF:
        await failConnection(conn, H2ErrFlowControlError)
        return
      conn.remoteWindowSize = newWindow
      wakeConnectionWaiters(conn)
    elif frame.streamId in conn.streams:
      let s = conn.streams[frame.streamId]
      let newWindow = s.remoteWindowSize + int(increment)
      if newWindow > 0x7FFF_FFFF:
        await sendRstStream(conn, frame.streamId, H2ErrFlowControlError)
        conn.closeStream(frame.streamId)
        return
      s.remoteWindowSize = newWindow
      wakeWaiters(s.windowWaiters)
    elif (frame.streamId mod 2) == 0 or frame.streamId > conn.lastStreamId:
      await failConnection(conn, H2ErrProtocolError)
      return
    elif not conn.peerStreamWasOpened(frame.streamId):
      await failConnection(conn, H2ErrProtocolError)
      return

  of FramePing:
    if frame.streamId != 0:
      await failConnection(conn, H2ErrProtocolError)
      return
    if frame.payload.len != 8:
      await failConnection(conn, H2ErrFrameSizeError)
      return
    if (frame.flags and FlagAck) == 0:
      await sendFrame(conn, Http2Frame(
        frameType: FramePing,
        flags: FlagAck,
        streamId: 0,
        payload: frame.payload
      ))

  of FramePriority:
    if frame.payload.len != 5:
      await failConnection(conn, H2ErrFrameSizeError)
      return
    if frame.streamId == 0:
      await failConnection(conn, H2ErrProtocolError)
      return
    var dependency = 0'u32
    if not extractPriorityDependency(frame, dependency):
      await failConnection(conn, H2ErrProtocolError)
      return
    if dependency == frame.streamId:
      if frame.streamId in conn.streams:
        await sendRstStream(conn, frame.streamId, H2ErrProtocolError)
        conn.closeStream(frame.streamId)
      else:
        await failConnection(conn, H2ErrProtocolError)
      return

  of FrameGoAway:
    if frame.streamId != 0:
      await failConnection(conn, H2ErrProtocolError)
      return
    if frame.payload.len < 8:
      await failConnection(conn, H2ErrFrameSizeError)
      return
    conn.running = false

  of FrameRstStream:
    if frame.payload.len != 4:
      await failConnection(conn, H2ErrFrameSizeError)
      return
    if frame.streamId == 0:
      await failConnection(conn, H2ErrProtocolError)
      return
    if (frame.streamId mod 2) == 0 or frame.streamId > conn.lastStreamId:
      await failConnection(conn, H2ErrProtocolError)
      return
    if frame.streamId notin conn.streams and not conn.peerStreamWasOpened(frame.streamId):
      await failConnection(conn, H2ErrProtocolError)
      return
    conn.closeStream(frame.streamId)

  of FramePushPromise:
    await failConnection(conn, H2ErrProtocolError)

  else:
    discard

proc processServerFrame*(conn: Http2ServerConnection,
                         frame: Http2Frame): CpsVoidFuture =
  ## Apply an incoming HTTP/2 frame to server connection state. HEADERS and
  ## CONTINUATION parsing is synchronous until it encounters an actual write;
  ## forwarding that future avoids three nested CPS result objects per normal
  ## request while preserving the general async path for all other frame types.
  if conn.continuationStreamId != 0 and
      (frame.frameType != FrameContinuation or
       frame.streamId != conn.continuationStreamId):
    return failConnection(conn, H2ErrProtocolError)

  case frame.frameType
  of FrameHeaders:
    processHeadersFrame(conn, frame)
  of FrameContinuation:
    processContinuationFrame(conn, frame)
  else:
    processServerFrameSlow(conn, frame)

proc handleHttp2Connection*(stream: AsyncStream, config: HttpServerConfig,
                            handler: HttpHandler,
                            remoteAddr: string = "",
                            shutdownFlag: ptr bool = nil): CpsVoidFuture {.cps.} =
  ## Run the HTTP/2 server loop for one connection.
  let conn = newHttp2ServerConnection(stream, config, handler, shutdownFlag, remoteAddr)
  var sendTerminalGoAway = false
  var terminalGoAwayErr = H2ErrInternalError

  try:
    await readConnectionPreface(conn)
    await sendServerSettings(conn)

    while conn.running:
      let drainRequested = not conn.shutdownFlag.isNil and conn.shutdownFlag[]
      if drainRequested and conn.acceptingNewStreams:
        conn.acceptingNewStreams = false
        await sendGoAway(conn, H2ErrNoError)

      if drainRequested and conn.streams.len == 0:
        break

      let frame = await recvServerFrame(conn)
      await processServerFrame(conn, frame)

      if drainRequested and conn.streams.len == 0:
        break
  except CatchableError:
    if conn.running and not conn.goAwaySent:
      let msg = getCurrentExceptionMsg().toLowerAscii
      var shouldSend = true
      if "short frame header" in msg:
        shouldSend = false
      elif "frame size" in msg or "frame length" in msg:
        terminalGoAwayErr = H2ErrFrameSizeError
      elif "flow-control" in msg:
        terminalGoAwayErr = H2ErrFlowControlError
      elif "preface" in msg:
        terminalGoAwayErr = H2ErrProtocolError
      else:
        terminalGoAwayErr = H2ErrInternalError
      sendTerminalGoAway = shouldSend

  if sendTerminalGoAway and conn.running and not conn.goAwaySent:
    try:
      await sendGoAway(conn, terminalGoAwayErr)
    except CatchableError:
      discard

  let connErr = newException(system.IOError, "HTTP/2 connection closing")
  conn.running = false
  let pendingWrite = conn.writerWrite
  conn.writerWrite = nil
  if not pendingWrite.isNil and not pendingWrite.finished:
    pendingWrite.cancel()
  conn.failWriterCompletions(connErr)
  conn.failPendingOutbound(connErr)
  conn.writerRunning = false

  conn.failConnectionWaiters(connErr)
  for sid, s in conn.streams:
    if s.adapter != nil:
      s.adapter.feedEof()
    failWaiters(s.windowWaiters, connErr)

  conn.streamGroup.cancelAll()
  try:
    await conn.streamGroup.wait()
  except CatchableError:
    discard

  stream.close()
