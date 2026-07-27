package packetproxy.gui

import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import javax.swing.*
import packetproxy.controller.InterceptController
import packetproxy.model.InterceptModel
import packetproxy.util.Logging.errWithStackTrace

class GUIIntercept(private var owner: JFrame) : PropertyChangeListener {
  private var controller = InterceptController.getInstance()
  private var model = InterceptModel.getInstance()
  private lateinit var forward: JButton
  private lateinit var drop: JButton
  private lateinit var enabled: JToggleButton
  private lateinit var tabs: TabSet
  private lateinit var serverNamePanel: GUIServerNamePanel
  private var rawOriginal = ByteArray(0)
  private var original = ByteArray(0)

  init {
    model.addPropertyChangeListener(this)
  }

  fun createPanel(): JComponent {
    enabled =
      JToggleButton("intercept is off").apply {
        addActionListener {
          if (isSelected) controller.enableInterceptMode()
          else controller.disableInterceptMode(interceptData)
        }
      }
    forward =
      JButton("forward").apply {
        isEnabled = false
        addActionListener {
          try {
            controller.forward(interceptData)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    drop =
      JButton("drop").apply {
        isEnabled = false
        addActionListener {
          try {
            controller.drop()
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    serverNamePanel = GUIServerNamePanel()
    tabs = TabSet(true, false)
    return JPanel().apply {
      layout = BoxLayout(this, BoxLayout.Y_AXIS)
      add(
        JPanel().apply {
          add(enabled)
          add(forward)
          add(drop)
        }
      )
      add(serverNamePanel)
      add(tabs.tabPanel)
    }
  }

  private val interceptData: ByteArray
    get() =
      when (tabs.selectedIndex) {
        0 -> if (rawOriginal.contentEquals(tabs.raw.getData())) original else tabs.raw.getData()
        1 -> tabs.binary.getData()
        else -> tabs.json.getData()
      }

  override fun propertyChange(event: PropertyChangeEvent) {
    try {
      enabled.text = if (model.isInterceptEnabled()) "intercept is on" else "intercept is off"
      var data = model.getData() ?: ByteArray(0)
      var client = model.getClientPacket()
      var server = model.getServerPacket()
      serverNamePanel.updateServerName(client, server)
      tabs.setData(data)
      rawOriginal = tabs.raw.getData()
      original = data
      forward.isEnabled = client != null || server != null
      drop.isEnabled = forward.isEnabled
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
