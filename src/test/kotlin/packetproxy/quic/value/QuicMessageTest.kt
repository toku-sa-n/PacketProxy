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

package packetproxy.quic.value

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuicMessageTest {

  @Test
  fun 一つのQuicMessageをparseできること() {
    val testData = Hex.decodeHex("00000000000000030000000000000001ab".toCharArray())
    val msgs = QuicMessages.parse(testData)
    assertThat(msgs.get(0).data).isEqualTo(Hex.decodeHex("ab".toCharArray()))
  }

  @Test
  fun 複数のQuicMessageをparseできること() {
    val data =
      Hex.decodeHex(
        "00000000000000030000000000000001ab000000000000000100000000000000021234".toCharArray()
      )
    val msgs = QuicMessages.parse(data)
    assertThat(msgs.size()).isEqualTo(2)
    assertThat(msgs.get(0).streamId).isEqualTo(StreamId.of(0x3))
    assertThat(msgs.get(0).data).isEqualTo(Hex.decodeHex("ab".toCharArray()))
    assertThat(msgs.get(1).streamId).isEqualTo(StreamId.of(0x1))
    assertThat(msgs.get(1).data).isEqualTo(Hex.decodeHex("1234".toCharArray()))
  }

  @Test
  fun streamIdIsが動作すること() {
    val data =
      Hex.decodeHex(
        "00000000000000030000000000000001ab000000000000000100000000000000021234".toCharArray()
      )
    val msgs = QuicMessages.parse(data)
    val msg = msgs.get(0)
    assertThat(msg.streamIdIs(StreamId.of(0x3))).isTrue()
    assertThat(msg.streamIdIs(StreamId.of(0x4))).isFalse()
  }
}
