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

import java.awt.Dimension
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.SpringLayout
import packetproxy.http.Http
import packetproxy.model.OneShotPacket
import packetproxy.model.Packet
import packetproxy.model.PacketInfo
import packetproxy.util.errWithStackTrace

class GUIServerNamePanel : JPanel() {
  private val clientLabel = JLabel(" ")
  private val serverLabel = JLabel(" ")

  init {
    preferredSize = Dimension(100, 24)
    minimumSize = Dimension(10, 24)
    maximumSize = Dimension(1000, 24)
    var layout = SpringLayout()
    this.layout = layout
    clientLabel.horizontalAlignment = JLabel.LEFT
    clientLabel.verticalAlignment = JLabel.TOP
    layout.putConstraint(SpringLayout.WEST, clientLabel, 10, SpringLayout.WEST, this)
    layout.putConstraint(SpringLayout.NORTH, clientLabel, 4, SpringLayout.NORTH, this)
    add(clientLabel)
    serverLabel.horizontalAlignment = JLabel.LEFT
    serverLabel.verticalAlignment = JLabel.TOP
    layout.putConstraint(SpringLayout.WEST, serverLabel, 0, SpringLayout.EAST, clientLabel)
    layout.putConstraint(SpringLayout.NORTH, serverLabel, 4, SpringLayout.NORTH, this)
    add(serverLabel)
  }

  fun updateServerName(packet: OneShotPacket?) {
    updateServerName(packet?.getData(), packet)
  }

  fun updateServerName(clientPacket: Packet?, serverPacket: Packet?) {
    var targetPacket = serverPacket ?: clientPacket
    updateServerName(clientPacket?.getModifiedData(), targetPacket)
  }

  private fun updateServerName(clientData: ByteArray?, packet: PacketInfo?) {
    try {
      if (packet == null) {
        clearText()
        return
      }
      clientLabel.text = if (packet.getDirection() == Packet.Direction.CLIENT) " -> " else " <- "
      serverLabel.text =
        if (clientData != null && Http.isHTTP(clientData)) {
          var http = Http.create(clientData)
          "${http.getURL(packet.getServerPort(), packet.getUseSSL())} (${packet.getEncoder()})"
        } else {
          "${packet.getServerIP()}:${packet.getServerPort()} (${packet.getEncoder()})"
        }
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  private fun clearText() {
    clientLabel.text = " "
    serverLabel.text = " "
  }
}
