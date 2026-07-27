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

package packetproxy.quic.service.pnspace

import java.util.Optional
import org.assertj.core.api.AssertionsForClassTypes.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import packetproxy.quic.service.pnspace.helper.SentPackets
import packetproxy.quic.value.PacketNumber
import packetproxy.quic.value.SentPacket
import packetproxy.quic.value.frame.AckFrame
import packetproxy.quic.value.frame.helper.AckRanges
import packetproxy.quic.value.packet.helper.TestPacket

class SentPacketsTest {

  lateinit var sentPackets: SentPackets

  @BeforeEach
  fun beforeEach() {
    sentPackets = SentPackets()
  }

  @Test
  fun getLargestAckFrameが動作すること() {
    this.sentPackets.add(
      SentPacket(
        TestPacket.of(PacketNumber.of(0L), AckFrame(0L, 0L, 0L, 0L, AckRanges.emptyAckRanges))
      )
    )
    this.sentPackets.add(SentPacket(TestPacket.of(PacketNumber.of(1L))))
    this.sentPackets.add(
      SentPacket(
        TestPacket.of(PacketNumber.of(2L), AckFrame(2L, 0L, 0L, 0L, AckRanges.emptyAckRanges))
      )
    )
    this.sentPackets.add(SentPacket(TestPacket.of(PacketNumber.of(3L))))
    this.sentPackets.add(SentPacket(TestPacket.of(PacketNumber.of(4L))))
    this.sentPackets.add(
      SentPacket(
        TestPacket.of(PacketNumber.of(5L), AckFrame(1L, 0L, 0L, 0L, AckRanges.emptyAckRanges))
      )
    )
    this.sentPackets.add(SentPacket(TestPacket.of(PacketNumber.of(6L))))

    val a = sentPackets.getLargestAckFrame()
    assertThat(a).hasValue(AckFrame(2L, 0L, 0L, 0L, AckRanges.emptyAckRanges))
  }

  @Test
  fun getLargestAckFrameがEmptyになること() {
    this.sentPackets.add(SentPacket(TestPacket.of(PacketNumber.of(1L))))
    this.sentPackets.add(SentPacket(TestPacket.of(PacketNumber.of(3L))))
    this.sentPackets.add(SentPacket(TestPacket.of(PacketNumber.of(4L))))
    this.sentPackets.add(SentPacket(TestPacket.of(PacketNumber.of(6L))))

    assertThat(sentPackets.getLargestAckFrame()).isEqualTo(Optional.empty<AckFrame>())
  }
}
