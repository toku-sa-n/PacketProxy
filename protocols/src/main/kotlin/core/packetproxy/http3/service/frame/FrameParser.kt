/*
 * Copyright 2022 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.http3.service.frame

import com.google.common.collect.Sets
import java.lang.reflect.Modifier
import java.nio.ByteBuffer
import java.nio.file.Paths
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.StandardLocation
import javax.tools.ToolProvider
import packetproxy.http3.utils.parseVarInt
import packetproxy.http3.value.frame.Frame
import packetproxy.http3.value.frame.Frames
import packetproxy.http3.value.frame.GreaseFrame
import packetproxy.util.Logging.errWithStackTrace

open class FrameParser {
  companion object {
    private const val framePackage = "packetproxy.http3.value.frame"
    private val frameClass = Frame::class.java
    private val frameMap: MutableMap<Long, Class<Frame>> = HashMap()

    init {
      try {
        val compiler = ToolProvider.getSystemJavaCompiler()
        val fm = compiler.getStandardFileManager(DiagnosticCollector<JavaFileObject>(), null, null)
        val kind = Sets.newHashSet(JavaFileObject.Kind.CLASS)
        for (f in fm.list(StandardLocation.CLASS_PATH, framePackage, kind, true)) {
          val encodeFilePath = Paths.get(f.name)
          if (encodeFilePath.toString().contains("test")) {
            continue
          }
          val encodeClassPath =
            encodeFilePath
              .toString()
              .replace("/", ".")
              .replaceFirst(("^.*" + framePackage).toRegex(), framePackage)
              .replace("\\.class.*$".toRegex(), "")
          val klass = Class.forName(encodeClassPath)
          if (
            frameClass.isAssignableFrom(klass) &&
              !Modifier.isAbstract(klass.modifiers) &&
              !frameClass.isNestmateOf(klass)
          ) {
            val types = klass.getMethod("supportedTypes").invoke(null) as List<*>
            types.forEach { type -> frameMap[type as Long] = klass as Class<Frame> }
          }
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    @JvmStatic
    @Throws(Exception::class)
    fun parse(bytes: ByteArray): Frames = parse(ByteBuffer.wrap(bytes))

    @JvmStatic
    @Throws(Exception::class)
    fun parse(buffer: ByteBuffer): Frames {
      val frames = Frames.emptyList()
      while (buffer.hasRemaining()) {
        val type = getTypeWithoutIncrement(buffer)
        val klass = frameMap[type]
        if (klass == null) {
          frames.add(GreaseFrame.parse(buffer))
        } else {
          frames.add(createInstance(klass, buffer))
        }
      }
      return frames
    }

    @Throws(Exception::class)
    private fun createInstance(klass: Class<Frame>, buffer: ByteBuffer): Frame =
      klass.getMethod("parse", ByteBuffer::class.java).invoke(null, buffer) as Frame

    private fun getTypeWithoutIncrement(buffer: ByteBuffer): Long {
      val saved = buffer.position()
      val type = parseVarInt(buffer)
      buffer.position(saved)
      return type
    }
  }
}
