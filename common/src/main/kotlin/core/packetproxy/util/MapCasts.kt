package packetproxy.util

fun Any?.asStringKeyMap(): Map<String, Any?>? {
  if (this !is Map<*, *>) return null
  val out = LinkedHashMap<String, Any?>(this.size)
  for ((k, v) in this) {
    if (k !is String) return null
    out[k] = v
  }
  return out
}

fun Any?.asMutableStringKeyMap(): MutableMap<String, Any?>? {
  if (this is MutableMap<*, *>) {
    val out = LinkedHashMap<String, Any?>()
    for ((k, v) in this) {
      if (k !is String) return null
      out[k] = v
    }
    return out
  }
  return asStringKeyMap()?.toMutableMap()
}
