package packetproxy.quic.service.transportparameter

import com.google.common.collect.Sets
import java.lang.reflect.Modifier
import java.nio.ByteBuffer
import java.nio.file.Paths
import javax.tools.*
import packetproxy.quic.value.VariableLengthInteger
import packetproxy.quic.value.transportparameter.TransportParameter
import packetproxy.quic.value.transportparameter.UnknownParameter

class TransportParameterParser {
  private val pkg = "packetproxy.quic.value.transportparameter"
  private val cls = TransportParameter::class.java
  private var map: MutableMap<Long, Class<out TransportParameter>>? = null

  @Throws(Exception::class)
  fun parse(buffer: ByteBuffer): TransportParameter {
    val saved = buffer.position()
    val type = VariableLengthInteger.parse(buffer).value
    buffer.position(saved)
    if (map == null) createMap()
    return createInstance(map!![type] ?: map!![UnknownParameter.ID]!!, buffer)
  }

  @Throws(Exception::class)
  private fun createInstance(klass: Class<out TransportParameter>, buffer: ByteBuffer) =
    klass.getConstructor(ByteBuffer::class.java).newInstance(buffer)

  @Throws(Exception::class)
  private fun createMap() {
    map = HashMap()
    val compiler = ToolProvider.getSystemJavaCompiler()
    val fm = compiler.getStandardFileManager(DiagnosticCollector<JavaFileObject>(), null, null)
    val kind = Sets.newHashSet(JavaFileObject.Kind.CLASS)
    for (f in fm.list(StandardLocation.CLASS_PATH, pkg, kind, true)) {
      val path =
        Paths.get(f.name)
          .toString()
          .replace("/", ".")
          .replaceFirst("^.*$pkg".toRegex(), pkg)
          .replace("""\.class.*$""".toRegex(), "")
      val klass = Class.forName(path)
      if (!cls.isAssignableFrom(klass) || Modifier.isAbstract(klass.modifiers)) continue
      val tpKlass = klass.asSubclass(TransportParameter::class.java)
      map!![klass.getField("ID").getLong(null)] = tpKlass
    }
  }
}
