package packetproxy.common

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
      javaClass.getResourceAsStream("/version")?.use {
        it.bufferedReader(Charsets.UTF_8).readText().trim()
      } ?: DEFAULT_VERSION
    } catch (_: java.io.IOException) {
      DEFAULT_VERSION
    }
}
