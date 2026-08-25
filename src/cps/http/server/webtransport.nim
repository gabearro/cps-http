## WebTransport server adapter hooks.

import cps/runtime
import cps/transform
import ../shared/webtransport as wt_shared

type
  WebTransportPolicyHook* = proc(origin: string, authority: string, path: string): bool {.closure.}
  WebTransportSessionHandler* = proc(session: wt_shared.WebTransportSession): CpsVoidFuture {.closure.}

proc acceptWebTransportSession*(sessionId: uint64,
                                authority: string,
                                path: string,
                                origin: string = "",
                                policyHook: WebTransportPolicyHook = nil,
                                handler: WebTransportSessionHandler = nil): CpsFuture[wt_shared.WebTransportSession] {.cps.} =
  ## Accept a WebTransport CONNECT request as a new session.
  if not policyHook.isNil:
    if not policyHook(origin, authority, path):
      raise newException(ValueError, "WebTransport session rejected by server policy")
  let session = wt_shared.acceptWebTransportSession(sessionId, authority, path)
  if not handler.isNil:
    await handler(session)
  return session

proc parseConnectRequest*(headers: openArray[(string, string)]): wt_shared.WebTransportConnectRequest =
  ## Parse connect request from its encoded representation.
  wt_shared.parseWebTransportConnectHeaders(headers)

proc isWebTransportConnectRequest*(headers: openArray[(string, string)]): bool =
  ## Return whether the headers describe a WebTransport CONNECT request.
  wt_shared.isWebTransportConnectRequest(headers)
