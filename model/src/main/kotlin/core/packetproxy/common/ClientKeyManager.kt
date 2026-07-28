package packetproxy.common

import javax.net.ssl.KeyManager
import packetproxy.model.ClientCertificates
import packetproxy.model.Database
import packetproxy.model.Server
import packetproxy.util.errWithStackTrace

class ClientKeyManager {
  private val keyManagersHashMap = HashMap<Int, Array<KeyManager>>()

  @Throws(Exception::class)
  fun initialize(clientCertificates: ClientCertificates, database: Database) {
    for (certificate in clientCertificates.queryEnabled()) {
      try {
        setKeyManagers(certificate.getServer(database), certificate.load())
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  fun setKeyManagers(server: Server?, keyManagers: Array<KeyManager>) {
    server ?: return
    keyManagersHashMap[server.getId()] = keyManagers
  }

  fun getKeyManagers(server: Server?): Array<KeyManager>? =
    server?.let { keyManagersHashMap[it.getId()] }

  fun removeKeyManagers(server: Server?) {
    server ?: return
    keyManagersHashMap.remove(server.getId())
  }
}
