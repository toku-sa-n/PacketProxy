package packetproxy.common

import javax.net.ssl.KeyManager
import packetproxy.model.ClientCertificates
import packetproxy.model.Server
import packetproxy.util.Logging.errWithStackTrace

object ClientKeyManager {
  private val keyManagersHashMap = HashMap<Int, Array<KeyManager>>()

  @JvmStatic
  @Throws(Exception::class)
  fun initialize() {
    for (certificate in ClientCertificates.getInstance().queryEnabled()) {
      try {
        setKeyManagers(certificate.getServer(), certificate.load())
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  @JvmStatic
  fun setKeyManagers(server: Server?, keyManagers: Array<KeyManager>) {
    server ?: return
    keyManagersHashMap[server.getId()] = keyManagers
  }

  @JvmStatic
  fun getKeyManagers(server: Server?): Array<KeyManager>? =
    server?.let { keyManagersHashMap[it.getId()] }

  @JvmStatic
  fun removeKeyManagers(server: Server?) {
    server ?: return
    keyManagersHashMap.remove(server.getId())
  }
}
