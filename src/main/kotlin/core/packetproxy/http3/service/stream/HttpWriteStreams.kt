/*
 * Copyright 2023 DeNA Co., Ltd.
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
package packetproxy.http3.service.stream

import packetproxy.http3.service.HttpRaw
import packetproxy.http3.utils.quicMessageOf
import packetproxy.http3.value.frame.DataFrame
import packetproxy.http3.value.frame.HeadersFrame
import packetproxy.quic.value.QuicMessages

open class HttpWriteStreams : WriteStream {
  private val httpRaws = ArrayList<HttpRaw>()

  @Synchronized
  @Throws(Exception::class)
  override fun write(data: ByteArray) {
    /* not supported */
  }

  @Synchronized
  @Throws(Exception::class)
  fun write(httpRaw: HttpRaw) {
    httpRaws.add(httpRaw)
  }

  @Synchronized
  override fun readAllQuicMessages(): QuicMessages {
    val msgs = QuicMessages.emptyList()
    httpRaws.forEach { httpRaw ->
      /* Header と Body を一緒にする*/
      val headerBody =
        HeadersFrame.of(httpRaw.getEncodedHeader()).getBytes() +
          DataFrame.of(httpRaw.getBody()).getBytes()
      msgs.add(quicMessageOf(httpRaw.getStreamId(), headerBody))
    }
    httpRaws.clear()
    return msgs
  }
}
