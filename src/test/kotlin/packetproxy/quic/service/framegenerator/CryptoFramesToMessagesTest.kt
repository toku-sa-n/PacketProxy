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

package packetproxy.quic.service.framegenerator

import net.luminis.tls.handshake.ClientHello
import net.luminis.tls.handshake.HandshakeMessage
import org.apache.commons.codec.binary.Hex
import org.apache.commons.lang3.ArrayUtils
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import packetproxy.quic.value.frame.CryptoFrame

class CryptoFramesToMessagesTest {

  lateinit var stream: CryptoFramesToMessages
  lateinit var clientHelloBytes: ByteArray
  lateinit var clientHello: HandshakeMessage

  @BeforeEach
  fun before() {
    stream = CryptoFramesToMessages()
    clientHelloBytes =
      Hex.decodeHex(
        "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"
          .toCharArray()
      )
    clientHello = CryptoFramesToMessages.convertToHandshakeMessage(clientHelloBytes)
  }

  @Test
  fun 複数のHandshakeMessageを処理できる() {
    this.stream.write(CryptoFrame(0L, this.clientHelloBytes))
    this.stream.write(CryptoFrame(this.clientHelloBytes.size.toLong(), this.clientHelloBytes))
    val retMsg1 = this.stream.getHandshakeMessage()
    val retMsg2 = this.stream.getHandshakeMessage()
    assertThat(retMsg1.get()).isInstanceOf(ClientHello::class.java)
    assertThat(retMsg2.get()).isInstanceOf(ClientHello::class.java)
  }

  @Test
  fun 一つのHandshakeMessageが分割された状態でも処理できる() {
    val array1 = ArrayUtils.subarray(this.clientHelloBytes, 0, 10)
    val array2 = ArrayUtils.subarray(this.clientHelloBytes, 10, 50)
    val array3 = ArrayUtils.subarray(this.clientHelloBytes, 50, this.clientHelloBytes.size)

    val cryptoFrame1 = CryptoFrame(0L, array1)
    val cryptoFrame2 = CryptoFrame(10L, array2)
    val cryptoFrame3 = CryptoFrame(50L, array3)

    this.stream.write(cryptoFrame1)
    this.stream.write(cryptoFrame2)
    this.stream.write(cryptoFrame3)

    val ret = stream.getHandshakeMessage()
    assertThat(ret.get()).isInstanceOf(ClientHello::class.java)
  }

  @Test
  fun 一つのHandshakeMessageが分割されてシャフルされた状態でも処理できる() {
    val array1 = ArrayUtils.subarray(this.clientHelloBytes, 0, 10)
    val array2 = ArrayUtils.subarray(this.clientHelloBytes, 10, 50)
    val array3 = ArrayUtils.subarray(this.clientHelloBytes, 50, this.clientHelloBytes.size)

    val cryptoFrame1 = CryptoFrame(0L, array1)
    val cryptoFrame2 = CryptoFrame(10L, array2)
    val cryptoFrame3 = CryptoFrame(50L, array3)

    this.stream.write(cryptoFrame3)
    this.stream.write(cryptoFrame1)
    this.stream.write(cryptoFrame2)

    val ret = stream.getHandshakeMessage()
    assertThat(ret.get()).isInstanceOf(ClientHello::class.java)
  }

  @Test
  fun 複数のHandshakeMessageが分割されてシャフルされた状態でも処理できる() {
    val array10 = ArrayUtils.subarray(this.clientHelloBytes, 0, 10)
    val array40 = ArrayUtils.subarray(this.clientHelloBytes, 10, 50)
    val arrayRemaining = ArrayUtils.subarray(this.clientHelloBytes, 50, this.clientHelloBytes.size)

    val cryptoFrame1 = CryptoFrame(0L, array10)
    val cryptoFrame2 = CryptoFrame(10L, array40)
    val cryptoFrame3 = CryptoFrame(50L, arrayRemaining)
    val cryptoFrame4 = CryptoFrame(this.clientHelloBytes.size.toLong(), array10)
    val cryptoFrame5 = CryptoFrame(this.clientHelloBytes.size.toLong() + 10L, array40)
    val cryptoFrame6 = CryptoFrame(this.clientHelloBytes.size.toLong() + 50L, arrayRemaining)

    this.stream.write(cryptoFrame4)
    this.stream.write(cryptoFrame1)
    this.stream.write(cryptoFrame2)
    this.stream.write(cryptoFrame5)
    this.stream.write(cryptoFrame6)
    this.stream.write(cryptoFrame3)

    val ret1 = stream.getHandshakeMessage()
    val ret2 = stream.getHandshakeMessage()
    assertThat(ret1.get()).isInstanceOf(ClientHello::class.java)
    assertThat(ret2.get()).isInstanceOf(ClientHello::class.java)
  }

  @Test
  fun 一つのCryptoFrameに複数のHandshakeMessageが入った状態でも処理できる() {
    val array10 = ArrayUtils.subarray(this.clientHelloBytes, 0, 10)
    val array40 = ArrayUtils.subarray(this.clientHelloBytes, 10, 50)
    val arrayRemaining = ArrayUtils.subarray(this.clientHelloBytes, 50, this.clientHelloBytes.size)

    val cryptoFrame1 = CryptoFrame(0L, array10)
    val cryptoFrame2 = CryptoFrame(10L, array40)
    val cryptoFrame3 = CryptoFrame(50L, (arrayRemaining + array10))
    /* 次のMessageが混じった状態 */
    val cryptoFrame4 = CryptoFrame(this.clientHelloBytes.size.toLong() + 10L, array40)
    val cryptoFrame5 = CryptoFrame(this.clientHelloBytes.size.toLong() + 50L, arrayRemaining)

    this.stream.write(cryptoFrame4)
    this.stream.write(cryptoFrame1)
    this.stream.write(cryptoFrame2)
    this.stream.write(cryptoFrame5)
    this.stream.write(cryptoFrame3)

    val ret1 = stream.getHandshakeMessage()
    val ret2 = stream.getHandshakeMessage()
    assertThat(ret1.get()).isInstanceOf(ClientHello::class.java)
    assertThat(ret2.get()).isInstanceOf(ClientHello::class.java)
  }
}
