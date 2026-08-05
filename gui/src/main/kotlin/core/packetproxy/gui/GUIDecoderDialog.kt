package packetproxy.gui

import javax.swing.JComponent
import javax.swing.JDialog
import packetproxy.common.i18nString
import packetproxy.model.OneShotPacket
import packetproxy.util.errWithStackTrace

class GUIDecoderDialog(private val owner: GUIMain) : JDialog(owner) {
  private val mainPanel = GUIPacketData(owner)

  init {
    title = i18nString("Decoder")
    val rectangle = owner.bounds
    val width = rectangle.width - 100
    val height = rectangle.height - 100
    setBounds(
      rectangle.x + rectangle.width / 2 - width / 2,
      rectangle.y + rectangle.height / 2 - height / 2,
      width,
      height,
    )
    contentPane.add(mainPanel.createPanel())
  }

  fun setData(data: ByteArray) {
    val oneShot = OneShotPacket()
    oneShot.setData(data)
    mainPanel.setOneShotPacket(oneShot)
  }

  fun createPanel(): JComponent = mainPanel.createPanel()

  fun showDialog() {
    try {
      isModal = false
      isVisible = true
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }
}
