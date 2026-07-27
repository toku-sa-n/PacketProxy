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

package packetproxy.quic.value.frame

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AckEcnFrameTest {

  @Test
  fun smoke() {
    val test = Hex.decodeHex("030a0001000105000102".toCharArray())
    val ackEcnFrame = AckEcnFrame.parse(test)
    assertThat(ackEcnFrame.etc0Count).isEqualTo(0)
    assertThat(ackEcnFrame.etc1Count).isEqualTo(1)
    assertThat(ackEcnFrame.ecnCeCount).isEqualTo(2)
  }

  @Test
  fun equalsが正常に動作すること() {
    val test = Hex.decodeHex("030a0001000105000102".toCharArray())
    val ackEcnFrame1 = AckEcnFrame.parse(test)
    val ackEcnFrame2 = AckEcnFrame.parse(test)
    assertThat(ackEcnFrame1).isEqualTo(ackEcnFrame2)
  }
}
