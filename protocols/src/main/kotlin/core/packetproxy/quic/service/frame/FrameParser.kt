package packetproxy.quic.service.frame

import com.google.common.collect.Sets
import java.lang.reflect.Modifier
import java.nio.ByteBuffer
import java.nio.file.Paths
import javax.tools.*
import packetproxy.quic.value.frame.Frame

class FrameParser {
  private val framePackage = "packetproxy.quic.value.frame"
  private val frameClass = Frame::class.java
  private var frameMap: MutableMap<Byte, Class<out Frame>>? = null

  private fun createFrameMap() {
    frameMap = HashMap()
    val compiler = ToolProvider.getSystemJavaCompiler()
    val fm = compiler.getStandardFileManager(DiagnosticCollector<JavaFileObject>(), null, null)
    val kind = Sets.newHashSet(JavaFileObject.Kind.CLASS)
    for (f in fm.list(StandardLocation.CLASS_PATH, framePackage, kind, true)) {
      val path =
        Paths.get(f.name)
          .toString()
          .replace("/", ".")
          .replaceFirst("^.*$framePackage".toRegex(), framePackage)
          .replace("""\.class.*$""".toRegex(), "")
      val klass = Class.forName(path)
      if (frameClass.isAssignableFrom(klass) && !Modifier.isAbstract(klass.modifiers)) {
        (klass.getMethod("supportedTypes").invoke(null) as List<Byte>).forEach {
          frameMap!![it] = klass as Class<out Frame>
        }
      }
    }
  }

  @Throws(Exception::class)
  fun create(buffer: ByteBuffer): Frame {
    val saved = buffer.position()
    val type = buffer.get()
    buffer.position(saved)
    if (frameMap == null) createFrameMap()
    val klass =
      frameMap!![type] ?: throw Exception(String.format("Error: unknown frame type: %x", type))
    return klass.getMethod("parse", ByteBuffer::class.java).invoke(null, buffer) as Frame
  }
}
