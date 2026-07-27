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
package packetproxy.encode

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.StringUtils
import packetproxy.model.Packet
import packetproxy.util.Logging.errWithStackTrace

abstract class Encoder {
  private val PIPE_SIZE = 65536
  private var clientOutputForFlowControl: PipedOutputStream? = null
  private var clientInputForFlowControl: PipedInputStream? = null
  private var serverOutputForFlowControl: PipedOutputStream? = null
  private var serverInputForFlowControl: PipedInputStream? = null
  private var ALPN: String? = null
  @JvmField var encode_mode: Int = 0

  constructor(alpn: String?) {
    this.ALPN = alpn
    init()
  }

  constructor() {
    this.ALPN = null
    init()
  }

  fun setALPN(ALPN: String?) {
    this.ALPN = ALPN
  }

  fun getALPN(): String? = this.ALPN

  abstract fun getName(): String

  @Throws(Exception::class) abstract fun checkDelimiter(input_data: ByteArray): Int

  @Throws(Exception::class)
  open fun checkRequestDelimiter(input_data: ByteArray): Int = checkDelimiter(input_data)

  @Throws(Exception::class)
  open fun checkResponseDelimiter(input_data: ByteArray): Int = checkDelimiter(input_data)

  @Throws(Exception::class) abstract fun decodeServerResponse(input_data: ByteArray): ByteArray

  @Throws(Exception::class) abstract fun encodeServerResponse(input_data: ByteArray): ByteArray

  @Throws(Exception::class) abstract fun decodeClientRequest(input_data: ByteArray): ByteArray

  @Throws(Exception::class) abstract fun encodeClientRequest(input_data: ByteArray): ByteArray

  protected var clientInputData = ByteArrayOutputStream()
  protected var serverInputData = ByteArrayOutputStream()

  /* 溜める */
  @Throws(Exception::class)
  open fun clientRequestArrived(input_data: ByteArray) {
    clientInputData.write(input_data)
  }

  @Throws(Exception::class)
  open fun serverResponseArrived(input_data: ByteArray) {
    serverInputData.write(input_data)
  }

  /* 画面に表示せず、送信パターン (画面に表示したくないコントロールデータの送信をしたいとき利用) */
  @Throws(Exception::class) open fun passThroughClientRequest(): ByteArray? = null

  @Throws(Exception::class) open fun passThroughServerResponse(): ByteArray? = null

  /* 画面に表示せず、送信しないパターン (まだデータが溜まっていない状態が存在するとき利用) */
  @Throws(Exception::class)
  open fun clientRequestAvailable(): ByteArray? {
    val ret = clientInputData.toByteArray()
    clientInputData.reset()
    return ret
  }

  @Throws(Exception::class)
  open fun serverResponseAvailable(): ByteArray? {
    val ret = serverInputData.toByteArray()
    serverInputData.reset()
    return ret
  }

  /**
   * 再送するときに、新しいコネクションを利用するか、それとも既存のコネクションを利用するかの使い分け true: 新しいコネクションを利用する (Default) false:
   * 既存のコネクションを利用する
   */
  open fun useNewConnectionForResend(): Boolean = true

  /**
   * 再送するときに、新しいエンコーダーを利用するか、それとも既存のエンコーダーを利用するかの使い分け true: 新しいエンコーダーを利用する (Default) false:
   * 既存のエンコーダーを利用する
   */
  open fun useNewEncoderForResend(): Boolean = true

  /** パケットのheadlineを返す。履歴ウィンドウで利用されます。 文字化けすると重たくなるのでデフォルトではASCIIで表示可能な部分のみ表示する */
  open fun getSummarizedRequest(packet: Packet): String {
    val data = packet.getDecodedData()
    var prefix = ArrayUtils.subarray(data, 0, Math.min(100, data.size))
    prefix = StringUtils.toAscii(prefix)
    return String(prefix)
  }

  open fun getSummarizedResponse(packet: Packet): String {
    val data = packet.getDecodedData()
    var prefix = ArrayUtils.subarray(data, 0, Math.min(100, data.size))
    prefix = StringUtils.toAscii(prefix)
    return String(prefix)
  }

  /** 再送時のみ呼び出されます。encode関数が実行される前に実行されます。 */
  @Throws(Exception::class)
  open fun procBeforeResendClientRequest(packet: Packet): ByteArray = packet.getModifiedData()

  @Throws(Exception::class)
  open fun procBeforeResendServerResponse(packet: Packet): ByteArray = packet.getModifiedData()

  /** client_packet, server_packetは変更禁止、読み込みのみで使う事 */
  @Throws(Exception::class)
  open fun decodeServerResponse(client_packet: Packet?, server_packet: Packet): ByteArray =
    decodeServerResponse(server_packet)

  @Throws(Exception::class)
  open fun encodeServerResponse(client_packet: Packet?, server_packet: Packet): ByteArray =
    encodeServerResponse(server_packet)

  @Throws(Exception::class)
  open fun decodeServerResponse(server_packet: Packet): ByteArray =
    decodeServerResponse(server_packet.getReceivedData())

  @Throws(Exception::class)
  open fun encodeServerResponse(server_packet: Packet): ByteArray =
    encodeServerResponse(server_packet.getModifiedData())

  @Throws(Exception::class)
  open fun decodeClientRequest(client_packet: Packet): ByteArray =
    decodeClientRequest(client_packet.getReceivedData())

  @Throws(Exception::class)
  open fun encodeClientRequest(client_packet: Packet): ByteArray =
    encodeClientRequest(client_packet.getModifiedData())

  /** PacketのContentTypeを返す */
  @Throws(Exception::class)
  open fun getContentType(client_packet: Packet?, server_packet: Packet): String =
    getContentType(server_packet.getDecodedData())

  @Throws(Exception::class) open fun getContentType(input_data: ByteArray): String = ""

  /** GroupId */
  @Throws(Exception::class) open fun setGroupId(packet: Packet) {}

  /** Flow Controls */
  @Throws(Exception::class)
  open fun putToClientFlowControlledQueue(output_data: ByteArray) {
    clientOutputForFlowControl!!.write(output_data)
    clientOutputForFlowControl!!.flush()
  }

  @Throws(Exception::class)
  open fun putToServerFlowControlledQueue(output_data: ByteArray) {
    serverOutputForFlowControl!!.write(output_data)
    serverOutputForFlowControl!!.flush()
  }

  @Throws(Exception::class)
  open fun closeClientFlowControlledQueue() {
    clientOutputForFlowControl!!.close()
  }

  @Throws(Exception::class)
  open fun closeServerFlowControlledQueue() {
    serverOutputForFlowControl!!.close()
  }

  open fun getClientFlowControlledInputStream(): InputStream = clientInputForFlowControl!!

  open fun getServerFlowControlledInputStream(): InputStream = serverInputForFlowControl!!

  private fun init() {
    try {
      clientOutputForFlowControl = PipedOutputStream()
      clientInputForFlowControl = PipedInputStream(clientOutputForFlowControl, PIPE_SIZE)
      serverOutputForFlowControl = PipedOutputStream()
      serverInputForFlowControl = PipedInputStream(serverOutputForFlowControl, PIPE_SIZE)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
