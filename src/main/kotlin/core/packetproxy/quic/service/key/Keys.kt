package packetproxy.quic.service.key

import java.nio.file.Files
import java.nio.file.Paths
import org.apache.commons.codec.binary.Hex
import packetproxy.quic.utils.Constants
import packetproxy.quic.value.ConnectionId
import packetproxy.util.Logging.errWithStackTrace

class Keys {
  val clientKeys = RoleKeys(Constants.Role.CLIENT)
  val serverKeys = RoleKeys(Constants.Role.SERVER)
  var clientRandom: ByteArray? = null

  fun computeInitialKey(id: ConnectionId) {
    clientKeys.computeInitialKey(id)
    serverKeys.computeInitialKey(id)
  }

  fun computeZeroRttKey(s: ByteArray) {
    clientKeys.computeZeroRttKey(s)
  }

  fun computeHandshakeKey(c: ByteArray, s: ByteArray) {
    clientKeys.computeHandshakeKey(c)
    serverKeys.computeHandshakeKey(s)
  }

  fun computeApplicationKey(c: ByteArray, s: ByteArray) {
    clientKeys.computeApplicationKey(c)
    serverKeys.computeApplicationKey(s)
    outputSecretsForWireshark()
  }

  fun hasInitialKey() = clientKeys.hasInitialKey()

  fun hasHandshakeKey() = clientKeys.hasHandshakeKey()

  fun hasApplicationKey() = clientKeys.hasApplicationKey()

  fun getRoleKeys(r: Constants.Role) = if (r == Constants.Role.CLIENT) clientKeys else serverKeys

  fun discardInitialKey() {
    clientKeys.discardInitialKey()
    serverKeys.discardInitialKey()
  }

  fun discardHandshakeKey() {
    clientKeys.discardHandshakeKey()
    serverKeys.discardHandshakeKey()
  }

  fun discardedInitialKey() = clientKeys.discardedInitialKey()

  fun discardedHandshakeKey() = clientKeys.discardedHandshakeKey()

  fun outputSecretsForWireshark() {
    if (clientRandom == null || !clientKeys.hasHandshakeKey() || !clientKeys.hasApplicationKey())
      return
    try {
      if (!Files.exists(logDir)) Files.createDirectories(logDir)
      keylogFile.toFile().bufferedWriter().use { f ->
        val r = Hex.encodeHexString(clientRandom)
        f.write(
          "CLIENT_HANDSHAKE_TRAFFIC_SECRET $r ${Hex.encodeHexString(clientKeys.handshakeKey.secret)}\n"
        )
        f.write(
          "SERVER_HANDSHAKE_TRAFFIC_SECRET $r ${Hex.encodeHexString(serverKeys.handshakeKey.secret)}\n"
        )
        f.write(
          "CLIENT_TRAFFIC_SECRET_0 $r ${Hex.encodeHexString(clientKeys.applicationKey.secret)}\n"
        )
        f.write(
          "SERVER_TRAFFIC_SECRET_0 $r ${Hex.encodeHexString(serverKeys.applicationKey.secret)}\n"
        )
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  companion object {
    private val logDir = Paths.get(System.getProperty("user.home") + "/.packetproxy/logs")
    private val keylogFile = Paths.get("$logDir/quic_tls.keylog")
  }
}
