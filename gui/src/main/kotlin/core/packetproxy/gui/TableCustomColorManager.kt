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
package packetproxy.gui

import java.awt.Color

class TableCustomColorManager {
  private class LineColor(private val packetId: Int, private val color: Color) {
    fun getPacketID(): Int = packetId

    fun getColor(): Color = color

    override fun toString(): String = "{$packetId:$color}"
  }

  private val coloredLines = HashMap<Int, LineColor>()

  fun add(packetId: Int, color: Color) {
    coloredLines[packetId] = LineColor(packetId, color)
  }

  fun clear(packetId: Int) {
    coloredLines.remove(packetId)
  }

  fun clear() {
    coloredLines.clear()
  }

  fun contains(packetId: Int): Boolean = coloredLines.containsKey(packetId)

  @Throws(Exception::class)
  fun getColor(packetId: Int): Color {
    return coloredLines[packetId]?.getColor() ?: throw Exception("line color is not registered.")
  }

  override fun toString(): String = "coloredLines: $coloredLines"
}
