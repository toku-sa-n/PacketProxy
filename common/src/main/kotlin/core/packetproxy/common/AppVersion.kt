package packetproxy.common

import org.apache.commons.io.IOUtils

class AppVersion {
  private val DEFAULT_VERSION = "1.0.0"
  private var cached: String? = null

  fun get(): String {
    if (cached == null) {
      cached = load()
    }
    return cached!!
  }

  private fun load(): String =
    try {
      javaClass.getResourceAsStream("/version")?.use { IOUtils.toString(it).trim() }
        ?: DEFAULT_VERSION
    } catch (_: java.io.IOException) {
      DEFAULT_VERSION
    }
}
