package packetproxy.common

import javax.net.ssl.SNIServerName

abstract class SSLCapabilities {
  abstract fun getRecordVersion(): String

  abstract fun getHelloVersion(): String

  abstract fun getServerNames(): List<SNIServerName>
}
