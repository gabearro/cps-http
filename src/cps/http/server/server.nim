## HTTP Server - Accept Loop and Lifecycle
##
## Server accept loop, graceful shutdown, and convenience serve() proc.

import cps/runtime
import cps/transform
import cps/eventloop
when defined(posix):
  import cps/concurrency/signals
import cps/concurrency/taskgroup
import std/[nativesockets, tables, os, net]
import cps/io/streams
import cps/io/tcp
import cps/tls/server as tls_server
import cps/quic/endpoint as quic_endpoint
import cps/quic/connection as quic_connection
import cps/quic/streams as quic_streams
import cps/quic/types as quic_types
import ./types
import ./http1
import ./http2
import ./http3 as http3_server
from ./http3 import Http3ProtocolViolation
import ../shared/http3
import ../shared/http3_connection
import ../shared/masque as masque_shared

export types

type H3SessionStore = ref object
  sessions: Table[pointer, http3_server.Http3ServerSession]
  initialized: Table[pointer, bool]
  quicEndpointPtr: pointer

proc remoteIp(client: TcpStream): string =
  ## Best-effort remote peer extraction for trusted proxy decisions.
  client.peerEndpoint().ip

proc handleAcceptedConnection(server: HttpServer, client: TcpStream,
                              tlsCtx: tls_server.TlsServerContext): CpsVoidFuture {.cps.} =
  # Formatting the peer address allocates. Only proxy trust evaluation needs
  # it; the normal HTTP path keeps accepted connections entirely descriptor-
  # based until request bytes arrive.
  let peerIp =
    if server.config.trustedForwardedHeaders: remoteIp(client)
    else: ""
  if server.config.useTls:
    let tlsStream = await tls_server.tlsAccept(tlsCtx, client)
    if server.config.enableHttp2 and tlsStream.alpnProto == "h2":
      await handleHttp2Connection(
        tlsStream.AsyncStream,
        server.config,
        server.handler,
        peerIp,
        addr server.shutdownStarted
      )
    else:
      await handleHttp1Connection(
        tlsStream.AsyncStream,
        server.config,
        server.handler,
        peerIp
      )
  else:
    await handleHttp1Connection(
      client.AsyncStream,
      server.config,
      server.handler,
      peerIp
    )

proc connRefKey(conn: quic_connection.QuicConnection): pointer {.inline.} =
  ## Connection refs are stable for their lifetime and the close callback
  ## removes their session before ARC/ORC can reuse the address.
  cast[pointer](conn)

proc newH3SessionStore(): H3SessionStore =
  new(result)
  result.sessions = initTable[pointer, http3_server.Http3ServerSession]()
  result.initialized = initTable[pointer, bool]()
  result.quicEndpointPtr = nil

proc setH3SessionStoreEndpoint(store: H3SessionStore,
                               ep: quic_endpoint.QuicEndpoint) {.inline.} =
  if store.isNil:
    return
  store.quicEndpointPtr = cast[pointer](ep)

proc h3SessionStoreEndpoint(store: H3SessionStore): quic_endpoint.QuicEndpoint {.inline.} =
  if store.isNil or store.quicEndpointPtr.isNil:
    return nil
  cast[quic_endpoint.QuicEndpoint](store.quicEndpointPtr)

proc getOrCreateH3Session(store: H3SessionStore,
                          conn: quic_connection.QuicConnection,
                          handler: HttpHandler,
                          maxRequestBodySize: int,
                          enableDatagram: bool): http3_server.Http3ServerSession =
  let key = connRefKey(conn)
  if key notin store.sessions:
    store.sessions[key] = http3_server.newHttp3ServerSession(
      conn.localConnId,
      handler,
      maxRequestBodySize = maxRequestBodySize,
      enableDatagram = enableDatagram
    )
  store.sessions[key]

proc removeH3Session(store: H3SessionStore,
                     conn: quic_connection.QuicConnection) =
  let key = connRefKey(conn)
  if key in store.sessions:
    store.sessions.del(key)
  if key in store.initialized:
    store.initialized.del(key)

proc clearH3SessionStore(store: H3SessionStore) =
  if store.isNil:
    return
  store.sessions.clear()
  store.initialized.clear()
  store.quicEndpointPtr = nil

proc closeHttp3ProtocolFailure(ep: quic_endpoint.QuicEndpoint,
                               conn: quic_connection.QuicConnection,
                               reasonText: string,
                               errorCode: uint64 = H3ErrGeneralProtocol): CpsVoidFuture {.cps.} =
  if conn.isNil or conn.state in {quic_connection.qcsClosed, quic_connection.qcsDraining}:
    return
  var reason = if reasonText.len > 0: reasonText else: "HTTP/3 protocol error"
  if reason.len > 120:
    reason = reason[0 ..< 120]
  if existsEnv("CPS_QUIC_DEBUG"):
    echo "[cps-http3] protocol-failure: ", reason
  conn.pendingControlFrames.add quic_types.QuicFrame(
    kind: quic_types.qfkConnectionClose,
    isApplicationClose: true,
    errorCode: if errorCode != 0'u64: errorCode else: H3ErrGeneralProtocol,
    frameType: 0'u64,
    reason: reason
  )
  try:
    await ep.flushPendingControl(conn)
  except CatchableError:
    conn.closeConnection()
    return
  if conn.state != quic_connection.qcsClosed:
    conn.state = quic_connection.qcsDraining

proc closeHttp3GracefullyIfReady(ep: quic_endpoint.QuicEndpoint,
                                 conn: quic_connection.QuicConnection,
                                 session: http3_server.Http3ServerSession): CpsVoidFuture {.cps.} =
  ## A peer GOAWAY starts graceful HTTP/3 shutdown. Drain every response that
  ## was already accepted, send our GOAWAY on the control stream, then finish
  ## the QUIC connection with H3_NO_ERROR so peers do not wait for idle expiry.
  if ep.isNil or conn.isNil or session.isNil or
      conn.state in {quic_connection.qcsClosed, quic_connection.qcsDraining} or
      not session.conn.hasPeerGoaway or session.hasPendingRequests() or
      session.conn.controlState == h3csGoawaySent:
    return

  let goaway = session.conn.sendGracefulServerGoaway()
  await ep.sendStreamData(
    conn,
    session.conn.controlStreamId,
    goaway,
    fin = false
  )

  # sendStreamData deliberately defers packet construction inside a receive
  # callback. Shutdown is the batch boundary: flush response and GOAWAY STREAM
  # frames before emitting CONNECTION_CLOSE.
  while conn.streamSendBatchActive():
    conn.endStreamSendBatch()
  await ep.flushPendingControl(conn)

  conn.pendingControlFrames.add quic_types.QuicFrame(
    kind: quic_types.qfkConnectionClose,
    isApplicationClose: true,
    errorCode: H3ErrNoError,
    frameType: 0'u64,
    reason: ""
  )
  await ep.flushPendingControl(conn)
  conn.setCloseReason(H3ErrNoError, "graceful HTTP/3 shutdown")
  conn.enterDraining()

proc currentExceptionOr(defaultMsg: string): string =
  let msg = getCurrentExceptionMsg()
  if msg.len > 0:
    return msg
  defaultMsg

proc currentHttp3ProtocolErrorCode(defaultCode: uint64 = H3ErrGeneralProtocol): uint64 =
  let ex = getCurrentException()
  if not ex.isNil and ex of Http3ProtocolViolation:
    let h3 = cast[Http3ProtocolViolation](ex)
    if h3.errorCode != 0'u64:
      return h3.errorCode
  defaultCode

proc flushHttp3QpackControlStreams(ep: quic_endpoint.QuicEndpoint,
                                   conn: quic_connection.QuicConnection,
                                   session: http3_server.Http3ServerSession): CpsVoidFuture {.cps.} =
  if conn.isNil or conn.state != quic_connection.qcsActive or
      not conn.canEncodePacketType(quic_types.qptShort):
    return
  let encoderUpdates = session.conn.drainQpackEncoderStreamData()
  if encoderUpdates.len > 0:
    await ep.sendStreamData(
      conn,
      session.conn.qpackEncoderStreamId,
      encoderUpdates,
      fin = false
    )
  let decoderUpdates = session.conn.drainQpackDecoderStreamData()
  if decoderUpdates.len > 0:
    await ep.sendStreamData(
      conn,
      session.conn.qpackDecoderStreamId,
      decoderUpdates,
      fin = false
    )

proc flushHttp3ApplicationQueues(ep: quic_endpoint.QuicEndpoint,
                                 conn: quic_connection.QuicConnection,
                                 session: http3_server.Http3ServerSession): CpsVoidFuture {.cps.} =
  if conn.isNil or session.isNil or conn.state != quic_connection.qcsActive or
      not conn.canEncodePacketType(quic_types.qptShort):
    return
  if session.conn.webTransportSessions.len == 0 and
      session.conn.masqueSessions.len == 0:
    return
  if session.conn.canSendH3Datagrams():
    let webtransportDatagrams = session.conn.popWebTransportOutgoingDatagrams()
    for dg in webtransportDatagrams:
      if dg.len > 0:
        await ep.sendDatagram(conn, dg)
    let masqueDatagrams = session.conn.popMasqueOutgoingDatagrams()
    for dg in masqueDatagrams:
      if dg.len > 0:
        await ep.sendDatagram(conn, dg)
  elif session.conn.peerSettingsReceived:
    # Peer disabled H3 DATAGRAM support; drop queued application datagrams.
    discard session.conn.popWebTransportOutgoingDatagrams()
    discard session.conn.popMasqueOutgoingDatagrams()

  let capsuleBatches = session.drainMasqueOutgoingCapsulesByStream()
  for batch in capsuleBatches:
    for capsule in batch.capsules:
      let capsuleWire = masque_shared.encodeCapsuleWire(capsule.capsuleType, capsule.payload)
      if capsuleWire.len == 0:
        continue
      let dataFrame = http3_connection.encodeDataFrame(capsuleWire)
      if dataFrame.len == 0:
        continue
      await ep.sendStreamData(
        conn,
        batch.streamId,
        dataFrame,
        fin = false
      )

proc hasHttp3ApplicationQueues(session: http3_server.Http3ServerSession): bool
    {.inline.} =
  ## Avoid constructing an asynchronous flush future for ordinary HTTP/3
  ## sessions that have never enabled WebTransport or MASQUE.
  not session.isNil and (session.conn.webTransportSessions.len > 0 or
    session.conn.masqueSessions.len > 0)

proc handleQuicHttp3Stream(ep: quic_endpoint.QuicEndpoint,
                           sessions: H3SessionStore,
                           handler: HttpHandler,
                           maxRequestBodySize: int,
                           enableDatagram: bool,
                           conn: quic_connection.QuicConnection,
                           streamId: uint64): CpsVoidFuture {.cps.} =
  if conn.isNil or conn.state in {quic_connection.qcsClosed, quic_connection.qcsDraining}:
    return
  let session = getOrCreateH3Session(
    sessions,
    conn,
    handler,
    maxRequestBodySize,
    enableDatagram
  )
  let streamObj = conn.getOrCreateStream(streamId)
  let reqBytes = quic_streams.popRecvData(streamObj, high(int))
  let streamEnded = streamObj.recvState == qrsDataRecvd

  if not quic_streams.isBidirectionalStream(streamId):
    if reqBytes.len == 0 and not streamEnded:
      if session.hasHttp3ApplicationQueues():
        await flushHttp3ApplicationQueues(ep, conn, session)
      return
    var events: seq[Http3Event] = @[]
    try:
      events = session.conn.ingestUniStreamData(streamId, reqBytes)
      if streamEnded:
        let finEvents = session.conn.finalizeUniStream(streamId)
        if finEvents.len > 0:
          events.add finEvents
    except CatchableError:
      await closeHttp3ProtocolFailure(
        ep,
        conn,
        currentExceptionOr("HTTP/3 unidirectional stream ingest failure"),
        H3ErrInternal
      )
      return
    for ev in events:
      if ev.kind == h3evProtocolError:
        await closeHttp3ProtocolFailure(
          ep,
          conn,
          if ev.errorMessage.len > 0: ev.errorMessage else: "HTTP/3 unidirectional stream protocol error",
          if ev.errorCode != 0'u64: ev.errorCode else: H3ErrGeneralProtocol
        )
        return
    if session.conn.hasPendingQpackStreamData():
      await flushHttp3QpackControlStreams(ep, conn, session)
    let blockedIds = session.qpackBlockedRequestStreamIds()
    if blockedIds.len > 0:
      for pendingStreamId in blockedIds:
        if not session.hasPendingRequestStream(pendingStreamId) or
            not session.isQpackBlockedRequestStream(pendingStreamId):
          continue
        let pendingStream = conn.getOrCreateStream(pendingStreamId)
        let pendingEnded = pendingStream.recvState == qrsDataRecvd
        var retryFrames: seq[byte] = @[]
        try:
          retryFrames = await session.handleHttp3RequestFrames(
            pendingStreamId,
            @[],
            streamEnded = pendingEnded
          )
        except Http3ProtocolViolation:
          await closeHttp3ProtocolFailure(
            ep,
            conn,
            currentExceptionOr("HTTP/3 blocked-request replay protocol failure"),
            currentHttp3ProtocolErrorCode()
          )
          return
        except CatchableError:
          await closeHttp3ProtocolFailure(
            ep,
            conn,
            currentExceptionOr("HTTP/3 blocked-request replay failure"),
            H3ErrInternal
          )
          return
        if retryFrames.len > 0:
          if conn.state != quic_connection.qcsActive or not conn.canEncodePacketType(quic_types.qptShort):
            return
          if session.conn.hasPendingQpackStreamData():
            await flushHttp3QpackControlStreams(ep, conn, session)
          let retryFin = not session.hasPendingRequestStream(pendingStreamId)
          await ep.sendStreamData(conn, pendingStreamId, retryFrames, fin = retryFin)
    if session.hasHttp3ApplicationQueues():
      await flushHttp3ApplicationQueues(ep, conn, session)
    if session.conn.hasPeerGoaway:
      await closeHttp3GracefullyIfReady(ep, conn, session)
    return

  if reqBytes.len == 0 and not streamEnded:
    if session.hasHttp3ApplicationQueues():
      await flushHttp3ApplicationQueues(ep, conn, session)
    return
  var respFrames: seq[byte] = @[]
  try:
    respFrames = await session.handleHttp3RequestFrames(
      streamId,
      reqBytes,
      streamEnded = streamEnded
    )
  except Http3ProtocolViolation:
    await closeHttp3ProtocolFailure(
      ep,
      conn,
      currentExceptionOr("HTTP/3 request stream protocol failure"),
      currentHttp3ProtocolErrorCode()
    )
    return
  except CatchableError:
    await closeHttp3ProtocolFailure(
      ep,
      conn,
      currentExceptionOr("HTTP/3 request stream processing failure"),
      H3ErrInternal
    )
    return
  if respFrames.len > 0:
    if conn.state != quic_connection.qcsActive or not conn.canEncodePacketType(quic_types.qptShort):
      return
    if session.conn.hasPendingQpackStreamData():
      await flushHttp3QpackControlStreams(ep, conn, session)
    let responseFin = not session.hasPendingRequestStream(streamId)
    await ep.sendStreamData(conn, streamId, respFrames, fin = responseFin)
  if session.hasHttp3ApplicationQueues():
    await flushHttp3ApplicationQueues(ep, conn, session)
  if session.conn.hasPeerGoaway:
    await closeHttp3GracefullyIfReady(ep, conn, session)

proc initializeQuicHttp3Connection(ep: quic_endpoint.QuicEndpoint,
                                   sessions: H3SessionStore,
                                   handler: HttpHandler,
                                   maxRequestBodySize: int,
                                   enableDatagram: bool,
                                   conn: quic_connection.QuicConnection): CpsVoidFuture {.cps.} =
  if conn.isNil or conn.state != quic_connection.qcsActive or
      not conn.canEncodePacketType(quic_types.qptShort):
    return
  let key = connRefKey(conn)
  if key in sessions.initialized and sessions.initialized[key]:
    return
  let session = getOrCreateH3Session(
    sessions,
    conn,
    handler,
    maxRequestBodySize,
    enableDatagram
  )
  let controlStream = conn.openLocalUniStream()
  await ep.sendStreamData(conn, controlStream.id, session.conn.encodeControlStreamPreface(), fin = false)
  let encStream = conn.openLocalUniStream()
  await ep.sendStreamData(conn, encStream.id, session.conn.encodeQpackEncoderStreamPreface(), fin = false)
  let decStream = conn.openLocalUniStream()
  await ep.sendStreamData(conn, decStream.id, session.conn.encodeQpackDecoderStreamPreface(), fin = false)
  sessions.initialized[key] = true

proc handleQuicDatagramEcho(ep: quic_endpoint.QuicEndpoint,
                            sessions: H3SessionStore,
                            enabled: bool,
                            conn: quic_connection.QuicConnection,
                            data: seq[byte]): CpsVoidFuture {.cps.} =
  var consumed = false
  var session: http3_server.Http3ServerSession = nil
  if data.len > 0 and not sessions.isNil:
    let key = connRefKey(conn)
    if key in sessions.sessions:
      session = sessions.sessions[key]
      if session.conn.canSendH3Datagrams():
        let routed = http3_server.routeH3Datagram(session, data)
        if routed.consumed:
          consumed = true
          for outDg in routed.outgoing:
            if outDg.len > 0:
              await ep.sendDatagram(conn, outDg)
      else:
        # Suppress QUIC datagram echo fallback on active HTTP/3 sessions when
        # H3 DATAGRAM has not been negotiated.
        consumed = true
      if session.hasHttp3ApplicationQueues():
        await flushHttp3ApplicationQueues(ep, conn, session)
  if not consumed and enabled and data.len > 0:
    await ep.sendDatagram(conn, data)

proc start*(server: HttpServer): CpsVoidFuture {.cps.} =
  ## Accept loop: accepts TCP connections and dispatches each to
  ## HTTP/1.1 or HTTP/2 handlers via the server's TaskGroup.
  ## Runs until server.running is set to false.
  var tlsCtx: tls_server.TlsServerContext = nil
  var quicEp: quic_endpoint.QuicEndpoint = nil
  let h3Sessions = newH3SessionStore()
  if server.config.useTls:
    let alpnProtos =
      if server.config.enableHttp2: @["h2", "http/1.1"]
      else: @["http/1.1"]
    tlsCtx = tls_server.newTlsServerContext(server.config.certFile, server.config.keyFile, alpnProtos)

  if server.config.enableHttp3:
    when not defined(useBoringSSL):
      raise newException(ValueError, "HTTP/3 requires build with -d:useBoringSSL")
    let datagramEnabled = server.config.quicEnableDatagram

    var quicCfg = quic_endpoint.defaultQuicEndpointConfig()
    quicCfg.quicIdleTimeoutMs = server.config.quicIdleTimeoutMs
    quicCfg.quicUseRetry = server.config.quicUseRetry
    quicCfg.quicEnableMigration = server.config.quicEnableMigration
    quicCfg.quicEnableDatagram = server.config.quicEnableDatagram
    quicCfg.quicMaxDatagramFrameSize = server.config.quicMaxDatagramFrameSize
    quicCfg.quicInitialMaxData = server.config.quicInitialMaxData
    quicCfg.quicInitialMaxStreamDataBidiLocal = server.config.quicInitialMaxStreamDataBidiLocal
    quicCfg.quicInitialMaxStreamDataBidiRemote = server.config.quicInitialMaxStreamDataBidiRemote
    quicCfg.quicInitialMaxStreamDataUni = server.config.quicInitialMaxStreamDataUni
    quicCfg.quicInitialMaxStreamsBidi = server.config.quicInitialMaxStreamsBidi
    quicCfg.quicInitialMaxStreamsUni = server.config.quicInitialMaxStreamsUni
    quicCfg.reusePort = server.config.reusePort
    quicCfg.tlsCertFile = server.config.certFile
    quicCfg.tlsKeyFile = server.config.keyFile
    quicCfg.alpn = @["h3"]
    if existsEnv("CPS_QUIC_DEBUG"):
      quicCfg.qlogSink = proc(event: string) =
        echo "[cps-quic] ", event

    let epRef = quic_endpoint.newQuicServerEndpoint(
      bindHost = server.config.host,
      bindPort = if server.boundPort > 0: server.boundPort else: server.config.port,
      onConnection = proc(conn: quic_connection.QuicConnection): CpsVoidFuture {.closure.} =
        discard conn
        completedVoidFuture(),
              onHandshakeState = proc(conn: quic_connection.QuicConnection,
                              state: quic_connection.QuicHandshakeState): CpsVoidFuture {.closure.} =
        if state == quic_connection.qhsOneRtt and conn.state == quic_connection.qcsActive:
          let ep = h3Sessions.h3SessionStoreEndpoint()
          if not ep.isNil:
            return initializeQuicHttp3Connection(
              ep,
              h3Sessions,
              server.handler,
              server.config.maxRequestBodySize,
              server.config.quicEnableDatagram,
              conn
            )
        completedVoidFuture(),
      onStreamReadable = proc(conn: quic_connection.QuicConnection,
                              streamId: uint64): CpsVoidFuture {.closure.} =
        let ep = h3Sessions.h3SessionStoreEndpoint()
        if ep.isNil:
          return completedVoidFuture()
        handleQuicHttp3Stream(
          ep,
          h3Sessions,
          server.handler,
          server.config.maxRequestBodySize,
          server.config.quicEnableDatagram,
          conn,
          streamId
        ),
      onDatagram = proc(conn: quic_connection.QuicConnection,
                        data: seq[byte]): CpsVoidFuture {.closure.} =
        let ep = h3Sessions.h3SessionStoreEndpoint()
        if ep.isNil:
          return completedVoidFuture()
        handleQuicDatagramEcho(ep, h3Sessions, datagramEnabled, conn, data),
      onConnectionClosed = proc(conn: quic_connection.QuicConnection,
                                errorCode: uint64,
                                reason: string): CpsVoidFuture {.closure.} =
        discard errorCode
        discard reason
        h3Sessions.removeH3Session(conn)
        completedVoidFuture(),
      config = quicCfg
    )
    h3Sessions.setH3SessionStoreEndpoint(epRef)
    quicEp = epRef
    quicEp.start()

  server.running = true
  server.acceptStopSignal = newCpsVoidFuture()
  for cb in server.onStartCallbacks:
    cb()
  try:
    server.listener.acceptEach(proc(client: TcpStream) =
      if not server.running:
        client.closeImmediately()
        return
      # Apply a hard cap on concurrent active connections.
      if server.config.maxConnections > 0 and server.connGroup.activeCount >= server.config.maxConnections:
        client.closeImmediately()
        return

      server.connGroup.spawn(handleAcceptedConnection(server, client, tlsCtx))
    , proc(err: ref CatchableError) =
      if server.running:
        server.running = false
        if not server.acceptStopSignal.finished:
          server.acceptStopSignal.fail(err)
    )
    await server.acceptStopSignal
  finally:
    if quicEp != nil:
      quicEp.shutdown(closeSocket = true)
    h3Sessions.clearH3SessionStore()
    if tlsCtx != nil:
      tls_server.closeTlsServerContext(tlsCtx)

proc shutdown*(server: HttpServer, drainTimeoutMs: int = 5000): CpsVoidFuture {.cps.} =
  ## Stop accepting new connections.
  ## Wait up to drainTimeoutMs for in-flight requests to complete.
  ## Cancel remaining connections after timeout.
  if server.shutdownStarted:
    return  # Idempotent: already shutting down
  server.shutdownStarted = true
  server.stop()
  for cb in server.onShutdownCallbacks:
    cb()
  # Wait for active connections to drain, with a timeout
  if server.connGroup.activeCount > 0:
    let waitFut = server.connGroup.wait()
    let timeoutFut = cpsSleep(drainTimeoutMs)
    while not waitFut.finished and not timeoutFut.finished:
      getEventLoop().tick()
    if not waitFut.finished:
      echo "Shutdown timeout: " & $server.connGroup.activeCount & " connections still active, cancelling"
      server.connGroup.cancelAll()

when defined(posix):
  proc shutdownOnSignal*(server: HttpServer, drainTimeoutMs: int = 5000): CpsVoidFuture {.cps.} =
    ## Register SIGINT/SIGTERM handlers that trigger graceful shutdown.
    ## Blocks until the signal is received and shutdown completes.
    initSignalHandling()
    await waitForShutdown()
    await shutdown(server, drainTimeoutMs)
    deinitSignalHandling()

proc serve*(handler: HttpHandler, port: int = 8080,
            host: string = "127.0.0.1",
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
            reusePort: bool = false,
            deferAcceptSeconds: int = 1,
            tcpNoDelay: bool = true,
            initialReadBufferBytes: int = 2048) =
  ## Convenience: create server, bind, start accept loop, run event loop.
  let server = newHttpServer(
    handler,
    host = host,
    port = port,
    useTls = useTls,
    certFile = certFile,
    keyFile = keyFile,
    enableHttp2 = enableHttp2,
    enableHttp3 = enableHttp3,
    quicIdleTimeoutMs = quicIdleTimeoutMs,
    quicUseRetry = quicUseRetry,
    quicEnableMigration = quicEnableMigration,
    quicEnableDatagram = quicEnableDatagram,
    quicMaxDatagramFrameSize = quicMaxDatagramFrameSize,
    quicInitialMaxData = quicInitialMaxData,
    quicInitialMaxStreamDataBidiLocal = quicInitialMaxStreamDataBidiLocal,
    quicInitialMaxStreamDataBidiRemote = quicInitialMaxStreamDataBidiRemote,
    quicInitialMaxStreamDataUni = quicInitialMaxStreamDataUni,
    quicInitialMaxStreamsBidi = quicInitialMaxStreamsBidi,
    quicInitialMaxStreamsUni = quicInitialMaxStreamsUni,
    reusePort = reusePort,
    deferAcceptSeconds = deferAcceptSeconds,
    tcpNoDelay = tcpNoDelay,
    initialReadBufferBytes = initialReadBufferBytes
  )
  server.bindAndListen()
  let scheme = if useTls: "https" else: "http"
  echo "Listening on " & scheme & "://" & host & ":" & $server.getPort()
  let loop = getEventLoop()
  discard server.start()
  while true:
    loop.tick()
