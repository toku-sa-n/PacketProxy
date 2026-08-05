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

/**
 * PACKETS の Int 通知（create は `-id`、update は `+id`）を packet id 単位でまとめる。
 *
 * create 通知が未処理のまま update で上書きされると、History 行が作られずレスポンスだけが 単独行（Streaming Packet）になるため、未処理の create は
 * update で潰さない。
 */
class PacketHistoryNotificationCoalescer {
  private val pending = LinkedHashMap<Int, Int>()

  /**
   * 通知を取り込む。
   *
   * @return 新たにドレインをスケジュールすべきなら true（先頭要素が入ったとき）
   */
  @Synchronized
  fun offer(value: Int): Boolean {
    val key = Math.abs(value)
    val wasEmpty = pending.isEmpty()
    val existing = pending[key]
    when {
      existing == null -> pending[key] = value
      existing < 0 && value >= 0 -> {
        // 未処理 create を update で潰さない。create 処理時に DB の最新状態を読む。
      }
      existing >= 0 && value < 0 -> pending[key] = value
      else -> pending[key] = value
    }
    return wasEmpty
  }

  /** 保留中の通知を取り出し、キューを空にする。挿入順を保つ。 */
  @Synchronized
  fun drain(): List<Int> {
    if (pending.isEmpty()) {
      return emptyList()
    }
    val copied = pending.values.toList()
    pending.clear()
    return copied
  }

  companion object {
    /** create 通知と update 通知を分け、create を先に返す（ペアリング用）。 */
    fun partitionCreatesBeforeUpdates(values: List<Int>): Pair<List<Int>, List<Int>> {
      val creates = ArrayList<Int>()
      val updates = ArrayList<Int>()
      for (value in values) {
        if (value < 0) {
          creates.add(value)
        } else {
          updates.add(value)
        }
      }
      return creates to updates
    }
  }
}
