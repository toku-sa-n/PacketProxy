package packetproxy.common

import org.apache.commons.io.IOUtils

object AppVersion {
  private const val DEFAULT_VERSION = "1.0.0"
  private var cached: String? = null

  @JvmStatic
  fun get(): String {
    if (cached == null) {
      cached = load()
    }
    return cached!!
  }

  private fun load(): String =
    try {
      AppVersion::class.java.getResourceAsStream("/version")?.use { IOUtils.toString(it).trim() }
        ?: DEFAULT_VERSION
    } catch (_: java.io.IOException) {
      DEFAULT_VERSION
    }
}
