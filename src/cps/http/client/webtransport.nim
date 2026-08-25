## WebTransport client adapter.

import cps/runtime
import cps/transform
import ../shared/webtransport as wt_shared

proc openWebTransportSession*(authority: string,
                              path: string,
                              sessionId: uint64 = 0'u64,
                              origin: string = ""): CpsFuture[wt_shared.WebTransportSession] {.cps.} =
  ## Create client-side WebTransport session state for a CONNECT request.
  return wt_shared.openWebTransportSession(
    sessionId = sessionId,
    authority = authority,
    path = path,
    origin = origin
  )

proc buildConnectHeaders*(authority: string,
                          path: string,
                          origin: string = ""): seq[(string, string)] =
  ## Build connect headers from the supplied state.
  wt_shared.buildWebTransportConnectHeaders(authority, path, origin = origin)

proc openBidiStream*(session: wt_shared.WebTransportSession): uint64 =
  ## Open bidi stream and initialize its protocol state.
  wt_shared.openBidiStream(session)

proc openUniStream*(session: wt_shared.WebTransportSession): uint64 =
  ## Open uni stream and initialize its protocol state.
  wt_shared.openUniStream(session)

proc sendDatagram*(session: wt_shared.WebTransportSession, payload: openArray[byte]) =
  ## Send datagram through the active transport.
  wt_shared.sendDatagram(session, payload)

proc recvDatagram*(session: wt_shared.WebTransportSession): seq[byte] =
  ## Receive datagram from the active transport.
  wt_shared.recvDatagram(session)

## Close session and release its owned resources.
proc closeSession*(session: wt_shared.WebTransportSession,
                   errorCode: uint32 = 0'u32,
                   reason: string = "") =
  ## Open web transport session and initialize its protocol state.
  wt_shared.closeSession(session, errorCode = errorCode, reason = reason)
