package packetproxy.gui

import java.awt.GridLayout
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.ScrollPaneConstants
import packetproxy.common.*
import packetproxy.model.Packet
import packetproxy.util.errWithStackTrace

class GUIDataAll(private val owner: GUIMain) {
  private val mainPanel = JPanel(GridLayout(1, 4))
  private val receivedText = createTextPane(i18nString("Received"))
  private val decodedText = createTextPane(i18nString("Decoded"))
  private val modifiedText = createTextPane(i18nString("Modified"))
  private val sentText = createTextPane(i18nString("Encoded"))

  fun createPanel(): JComponent = mainPanel

  fun setPacket(packet: Packet) {
    try {
      setText(receivedText, packet.getReceivedData())
      setText(decodedText, packet.getDecodedData())
      setText(modifiedText, packet.getModifiedData())
      setText(sentText, packet.getSentData())
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  private fun createTextPane(labelName: String): RawTextPane {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    val label = JLabel(labelName)
    label.alignmentX = 0.5f
    val text =
      RawTextPane(
        owner,
        owner.modelServices.fontManager,
        owner.modelServices.charSetUtility,
        owner.coreServices.packetProxyUtility,
      )
    text.isEditable = false
    panel.add(label)
    val scroll = JScrollPane(text)
    scroll.verticalScrollBarPolicy = ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
    scroll.horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
    panel.add(scroll)
    mainPanel.add(panel)
    return text
  }

  private fun setText(text: RawTextPane, data: ByteArray) {
    text.setData(data, true)
    text.caretPosition = 0
  }
}
