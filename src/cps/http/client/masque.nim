## MASQUE client adapter.

import cps/runtime
import cps/transform
import ../shared/masque as masque_shared

proc connectUdp*(authority: string, targetHostPort: string): CpsFuture[masque_shared.MasqueSession] {.cps.} =
  ## Create a MASQUE CONNECT-UDP request.
  return masque_shared.connectUdp(authority, targetHostPort)

proc connectIp*(authority: string, targetIpPrefix: string): CpsFuture[masque_shared.MasqueSession] {.cps.} =
  ## Create a MASQUE CONNECT-IP request.
  return masque_shared.connectIp(authority, targetIpPrefix)

proc buildConnectUdpHeaders*(authority: string, targetHostPort: string): seq[(string, string)] =
  ## Build connect UDP headers from the supplied state.
  masque_shared.buildMasqueConnectUdpHeaders(authority, targetHostPort)

proc buildConnectIpHeaders*(authority: string, targetIpPrefix: string): seq[(string, string)] =
  ## Build connect ip headers from the supplied state.
  masque_shared.buildMasqueConnectIpHeaders(authority, targetIpPrefix)

proc sendCapsule*(session: masque_shared.MasqueSession, capsuleType: uint64, payload: openArray[byte]) =
  ## Send capsule through the active transport.
  masque_shared.sendCapsule(session, capsuleType, payload)

proc recvCapsule*(session: masque_shared.MasqueSession): masque_shared.MasqueCapsule =
  ## Receive capsule from the active transport.
  masque_shared.recvCapsule(session)

proc openDatagramContext*(session: masque_shared.MasqueSession, label: string = ""): uint64 =
  ## Open datagram context and initialize its protocol state.
  masque_shared.openDatagramContext(session, label)

proc sendDatagram*(session: masque_shared.MasqueSession, contextId: uint64, payload: openArray[byte]) =
  ## Send datagram through the active transport.
  masque_shared.sendDatagram(session, contextId, payload)

proc recvDatagram*(session: masque_shared.MasqueSession): masque_shared.MasqueDatagram =
  ## Receive datagram from the active transport.
  masque_shared.recvDatagram(session)

proc encodeCapsuleWire*(capsuleType: uint64, payload: openArray[byte]): seq[byte] =
  ## Encode capsule wire into its wire representation.
  masque_shared.encodeCapsuleWire(capsuleType, payload)

proc decodeMasqueDatagramWire*(wire: openArray[byte]): masque_shared.MasqueDatagram =
  ## Decode masque datagram wire from its wire representation.
  masque_shared.decodeMasqueDatagramWire(wire)
