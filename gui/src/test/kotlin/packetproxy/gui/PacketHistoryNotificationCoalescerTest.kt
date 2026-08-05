/*
 * Copyright 2026 DeNA Co., Ltd.
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
package packetproxy.gui

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PacketHistoryNotificationCoalescerTest {
  @Test
  fun createThenUpdate_keepsCreateNotification() {
    // CLIENT create(-id) の直後に content_type などの update(+id) が来ても、
    // create を潰さないこと（潰すと History 行が作られずレスポンス単独行になる）
    val coalescer = PacketHistoryNotificationCoalescer()
    val packetId = 42

    assertThat(coalescer.offer(-packetId)).isTrue()
    assertThat(coalescer.offer(packetId)).isFalse()

    assertThat(coalescer.drain()).containsExactly(-packetId)
    assertThat(coalescer.drain()).isEmpty()
  }

  @Test
  fun updateThenCreate_prefersCreate() {
    val coalescer = PacketHistoryNotificationCoalescer()
    val packetId = 7

    coalescer.offer(packetId)
    coalescer.offer(-packetId)

    assertThat(coalescer.drain()).containsExactly(-packetId)
  }

  @Test
  fun latestUpdateWins_whenNoCreatePending() {
    val coalescer = PacketHistoryNotificationCoalescer()
    val packetId = 3

    coalescer.offer(packetId)
    coalescer.offer(packetId)

    assertThat(coalescer.drain()).containsExactly(packetId)
  }

  @Test
  fun latestCreateWins_whenMultipleCreates() {
    val coalescer = PacketHistoryNotificationCoalescer()
    val packetId = 9

    coalescer.offer(-packetId)
    coalescer.offer(-packetId)

    assertThat(coalescer.drain()).containsExactly(-packetId)
  }

  @Test
  fun preservesInsertionOrderAcrossPacketIds() {
    val coalescer = PacketHistoryNotificationCoalescer()

    coalescer.offer(-10) // CLIENT create
    coalescer.offer(10) // content_type update (must not overwrite create)
    coalescer.offer(-20) // SERVER create

    assertThat(coalescer.drain()).containsExactly(-10, -20)
  }

  @Test
  fun partitionCreatesBeforeUpdates_ordersCreatesFirst() {
    // drain 結果を create→update に分け、CLIENT 行登録後に SERVER をマージできるようにする
    val (creates, updates) =
      PacketHistoryNotificationCoalescer.partitionCreatesBeforeUpdates(listOf(5, -10, 11, -20))

    assertThat(creates).containsExactly(-10, -20)
    assertThat(updates).containsExactly(5, 11)
  }

  @Test
  fun createThenUpdateThenServerCreate_allowsRequestResponseMerge() {
    // 回帰: create が残り、同一 group の CLIENT→SERVER 順で処理すればマージ可能
    val coalescer = PacketHistoryNotificationCoalescer()
    val clientId = 100
    val serverId = 200
    val groupId = 55L
    val pairing = PacketPairingService()

    coalescer.offer(-clientId)
    coalescer.offer(clientId) // syncContentTypeToClient 相当
    coalescer.offer(-serverId)

    val notifications = coalescer.drain()
    val (creates, updates) =
      PacketHistoryNotificationCoalescer.partitionCreatesBeforeUpdates(notifications)

    assertThat(creates).containsExactly(-clientId, -serverId)
    assertThat(updates).isEmpty()

    // CLIENT create
    pairing.incrementGroupPacketCount(groupId)
    pairing.incrementGroupClientPacketCount(groupId)
    pairing.registerGroupRow(groupId, 0)
    assertThat(pairing.containsGroup(groupId)).isTrue()
    assertThat(pairing.isGroupMergeable(groupId)).isTrue()

    // SERVER create → マージ可能
    pairing.incrementGroupPacketCount(groupId)
    assertThat(pairing.hasResponse(groupId)).isFalse()
    assertThat(pairing.isGroupMergeable(groupId)).isTrue()
    assertThat(pairing.containsGroup(groupId)).isTrue()
  }
}
