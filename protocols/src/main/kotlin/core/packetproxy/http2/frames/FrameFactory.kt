/*
 * Copyright 2019 DeNA Co., Ltd.
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
package packetproxy.http2.frames

import org.eclipse.jetty.http2.hpack.HpackDecoder
import packetproxy.http2.frames.Frame.Type
import packetproxy.util.log

private val frameCreators: Map<Type, (Frame, HpackDecoder?) -> Frame> =
  mapOf(
    Type.DATA to { f, _ -> DataFrame(f) },
    Type.HEADERS to { f, decoder -> HeadersFrame(f, decoder) },
    Type.SETTINGS to { f, _ -> SettingsFrame(f) },
    Type.WINDOW_UPDATE to { f, _ -> WindowUpdateFrame(f) },
    Type.RST_STREAM to { f, _ -> RstStreamFrame(f) },
    Type.PING to { f, _ -> PingFrame(f) },
    Type.GOAWAY to { f, _ -> GoawayFrame(f) },
  )

@Throws(Exception::class)
fun create(type: Type, flags: Int, streamId: Int, payload: ByteArray): Frame =
  when (type) {
    Type.DATA -> DataFrame(flags, streamId, payload)
    else -> throw Exception("create Frames except DataFrame are not implemented yet")
  }

@Throws(Exception::class)
fun create(data: ByteArray, decoder: HpackDecoder?): Frame {
  val f = Frame(data)
  val creator = frameCreators[f.type]
  return if (creator != null) creator(f, decoder) else f
}

fun debug() {
  log(frameCreators.keys.toString())
}
