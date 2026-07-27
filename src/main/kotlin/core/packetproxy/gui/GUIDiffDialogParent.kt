package packetproxy.gui

import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import javax.swing.*
import javax.swing.event.ChangeListener
import packetproxy.util.Logging.errWithStackTrace

class GUIDiffDialogParent(owner: JFrame) : JDialog(owner) {
  private var mainPanel = JPanel()
  private var dataPane = JTabbedPane()
  private var rawPanel = GUIDiffRaw()
  private var binaryPanel = GUIDiffBinary()
  private var jsonPanel = GUIDiffJson()

  init {
    title = "Diff"
    var rect = owner.bounds
    setBounds(rect.x + 50, rect.y + 50, rect.width - 100, rect.height - 100)
    contentPane.layout = BoxLayout(contentPane, BoxLayout.Y_AXIS)
    contentPane.add(createPanel())
    addWindowListener(
      object : WindowAdapter() {
        override fun windowClosing(event: WindowEvent) {
          dispose()
        }
      }
    )
  }

  fun update() {
    try {
      when (dataPane.selectedIndex) {
        0 -> rawPanel.update()
        1 -> binaryPanel.update()
        2 -> jsonPanel.update()
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  fun showDialog() {
    try {
      update()
      isModal = true
      isVisible = true
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  fun createPanel(): JComponent {
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    dataPane.addTab("Raw", rawPanel.createPanel())
    dataPane.addTab("Binary", binaryPanel.createPanel())
    dataPane.addTab("Json", jsonPanel.createPanel())
    dataPane.addChangeListener(ChangeListener { update() })
    mainPanel.add(dataPane)
    return mainPanel
  }
}
