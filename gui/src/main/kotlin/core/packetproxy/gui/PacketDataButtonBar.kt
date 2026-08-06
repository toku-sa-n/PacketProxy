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

import java.awt.Dimension
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.border.LineBorder
import packetproxy.common.i18nString
import packetproxy.controller.SinglePacketAttackController
import packetproxy.model.Packet
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class PacketDataButtonBar(
  private val owner: GUIMain,
  private val history: GUIHistory,
  private val packetPanel: GUIPacket,
  private val resender: GUIResender,
  private val getActiveData: () -> ByteArray?,
  private val getContextPacket: () -> Packet?,
  private val getBodyData: () -> ByteArray?,
  private val getResponseData: () -> ByteArray?,
  private val markedOriginalRowHighlight: MarkedOriginalRowHighlight,
  private val resendDelegate: (() -> Unit)? = null,
) {
  private val charSetUtility = owner.modelServices.charSetUtility

  private val charSetCombo =
    JComboBox(charSetUtility.getAvailableCharSetList().toTypedArray()).apply {
      addActionListener {
        charSetUtility.setCharSet(selectedItem as String)
        runCatching { packetPanel.update() }.onFailure { errWithStackTrace(it) }
      }
      maximumSize = Dimension(150, maximumSize.height)
      addMouseListener(
        object : MouseAdapter() {
          override fun mousePressed(e: MouseEvent) {
            super.mousePressed(e)
            this@PacketDataButtonBar.updateCharSetCombo()
          }
        }
      )
      selectedItem = charSetUtility.getCharSetForGUIComponent()
    }

  private val copyUrlBodyButton =
    JButton(i18nString("copy Method+URL+Body")).apply {
      addActionListener {
        runCatching {
            val data = getActiveData() ?: return@addActionListener
            if (data.isEmpty()) {
              return@addActionListener
            }
            val packet = getContextPacket() ?: return@addActionListener
            copyMethodUrlBody(data, packet, charSetUtility)
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  private val copyBodyButton =
    JButton(i18nString("copy Body")).apply {
      alignmentX = 0.5f
      addActionListener {
        runCatching {
            val data = resolveDataForCopyBody() ?: return@addActionListener
            if (data.isEmpty()) {
              return@addActionListener
            }
            copyBody(data, charSetUtility)
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  private val copyUrlButton =
    JButton(i18nString("copy URL")).apply {
      alignmentX = 0.5f
      addActionListener {
        runCatching {
            val data = getActiveData() ?: return@addActionListener
            if (data.isEmpty()) {
              return@addActionListener
            }
            val packet = getContextPacket() ?: return@addActionListener
            copyUrl(data, packet, charSetUtility)
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  private val resendButton =
    JButton(i18nString("send")).apply {
      alignmentX = 0.5f
      addActionListener {
        runCatching {
            val delegate = resendDelegate
            if (delegate != null) {
              delegate()
              return@addActionListener
            }
            withActivePacket { data, packet, packetId ->
              owner.coreServices.resendController.resend(packet.getOneShotPacket(data))
              markResent(packet, packetId)
            }
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  private val resendMultipleButton =
    JButton(i18nString("send x 20")).apply {
      alignmentX = 0.5f
      addActionListener {
        runCatching {
            withActivePacket { data, packet, packetId ->
              owner.coreServices.resendController.resend(packet.getOneShotPacket(data), 20)
              markResent(packet, packetId)
            }
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  private val attackButton =
    JButton(i18nString("send x 20 (single-packet attack)")).apply {
      alignmentX = 0.5f
      addActionListener {
        runCatching {
            withActivePacket { data, packet, packetId ->
              SinglePacketAttackController(
                  packet.getOneShotPacket(data),
                  owner.coreServices.duplexFactory,
                  owner.coreServices.encoderManager,
                )
                .attack(20)
              markResent(packet, packetId)
            }
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  private val sendToResenderButton =
    JButton(i18nString("send to Resender")).apply {
      alignmentX = 0.5f
      addActionListener {
        runCatching {
            withActivePacket { data, packet, packetId ->
              packet.setResend()
              owner.modelServices.packets.update(packet)
              resender.addResends(packet.getOneShotPacket(data))
              history.updateRequestOne(packetId)
            }
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  private val stopDiffButton =
    JButton(i18nString("stop diff")).apply {
      alignmentX = 0.5f
      addActionListener {
        runCatching {
            if (!markedOriginalRowHighlight.hasMarkedOriginal) {
              return@addActionListener
            }
            owner.modelServices.diffModels.clearOriginal()
            markedOriginalRowHighlight.restoreMarkedRowAndClear()
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  private val diffButton =
    JButton(i18nString("diff!!")).apply {
      alignmentX = 0.5f
      addActionListener {
        runCatching {
            val data = resolveDataForDiff() ?: return@addActionListener
            owner.modelServices.diffModels.markAsTarget(data)
            GUIDiffDialogParent(owner).showDialog()
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  private val diffOrigButton =
    JButton(i18nString("mark as orig")).apply {
      alignmentX = 0.5f
      addActionListener {
        runCatching {
            val data = resolveDataForDiff() ?: return@addActionListener
            if (markedOriginalRowHighlight.hasMarkedOriginal) {
              owner.modelServices.diffModels.clearOriginal()
              markedOriginalRowHighlight.restoreMarkedRowAndClear()
            }
            owner.modelServices.diffModels.markAsOriginal(data)
            markedOriginalRowHighlight.markCurrentRowAsOriginal()
            log("Diff: original text was saved!")
          }
          .onFailure { errWithStackTrace(it) }
      }
    }

  fun createPanel(): JComponent {
    val diffPanel =
      JPanel().apply {
        add(diffOrigButton)
        add(diffButton)
        add(stopDiffButton)
        border = LineBorder(ThemeColors.borderColor(), 1, true)
        layout = BoxLayout(this, BoxLayout.LINE_AXIS)
      }

    val buttonPanel =
      JPanel().apply {
        add(charSetCombo)
        add(copyUrlBodyButton)
        add(copyBodyButton)
        add(copyUrlButton)
        add(resendButton)
        add(resendMultipleButton)
        add(attackButton)
        add(sendToResenderButton)
        add(JLabel(i18nString("  diff: ")))
        add(diffPanel)
        layout = BoxLayout(this, BoxLayout.LINE_AXIS)
      }

    val centeredPanel = ScrollableCenteredPanel()
    centeredPanel.add(buttonPanel)
    return createScrollPane(centeredPanel)
  }

  private fun updateCharSetCombo() {
    charSetCombo.removeAllItems()
    for (charSetName in charSetUtility.getAvailableCharSetList()) {
      charSetCombo.addItem(charSetName)
    }
    val charSetName = owner.modelServices.charSetUtility.getCharSetForGUIComponent()
    if (charSetUtility.getAvailableCharSetList().contains(charSetName)) {
      charSetCombo.selectedItem = charSetName
    } else {
      charSetCombo.selectedIndex = 0
    }
  }

  private inline fun withActivePacket(block: (ByteArray, Packet, Int) -> Unit) {
    val data = getActiveData() ?: return
    if (data.isEmpty()) {
      return
    }
    val packet = getContextPacket() ?: return
    block(data, packet, packet.getId())
  }

  private fun markResent(packet: Packet, packetId: Int) {
    packet.setResend()
    owner.modelServices.packets.update(packet)
    history.updateRequestOne(packetId)
  }

  private fun resolveDataForCopyBody(): ByteArray? =
    resolve(
      owner = owner,
      message = i18nString("Which body do you want to copy?"),
      title = i18nString("Select Copy Target"),
      isMergedRow = history.isSelectedRowMerged(),
      requestData = { getBodyData() },
      responseData = { getResponseData() },
    )

  private fun resolveDataForDiff(): ByteArray? =
    resolve(
      owner = owner,
      message = i18nString("Which data do you want to use for Diff?"),
      title = i18nString("Select Diff Target"),
      isMergedRow = history.isSelectedRowMerged(),
      requestData = { getActiveData() },
      responseData = { getResponseData() },
    )
}
