package packetproxy.gui

import java.awt.BorderLayout
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import javax.swing.JButton
import javax.swing.JPanel
import javax.swing.JTabbedPane
import packetproxy.common.Range
import packetproxy.model.PropertyChangeEventType.SELECTED_INDEX
import packetproxy.util.Logging.err
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.PacketProxyUtility
import packetproxy.util.SearchBox

class TabSet(search: Boolean, copy: Boolean) {
  private val changes = PropertyChangeSupport(this)
  private val rawPanel = GUIHistoryRaw()
  private val binaryPanel = GUIHistoryBinary()
  private val jsonPanel = GUIJson()
  private val dataPane = JTabbedPane()
  private val basePanel = JPanel(BorderLayout())
  private var copyButton: JButton? = null
  private var parentSendButton: JButton? = null
  private var data: ByteArray? = null
  private var emphasis: Range? = null
  private var searchBox: SearchBox? = null

  init {
    rawPanel.setParentTabs(this)
    binaryPanel.setParentTabs(this)
    dataPane.addTab("Raw", rawPanel.createPanel())
    dataPane.addTab("Binary", binaryPanel.createPanel())
    dataPane.addTab("Json", jsonPanel.createPanel())
    dataPane.addChangeListener {
      try {
        update()
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }
    basePanel.add(dataPane)
    if (search) {
      searchBox = SearchBox()
      basePanel.add(searchBox, BorderLayout.SOUTH)
    }
    if (copy) {
      copyButton = JButton("copy to clipboard")
      basePanel.add(copyButton)
    }
  }

  val tabPanel: JPanel
    get() = basePanel

  val raw: GUIHistoryRaw
    get() = rawPanel

  val binary: GUIHistoryBinary
    get() = binaryPanel

  val json: GUIJson
    get() = jsonPanel

  val selectedIndex: Int
    get() = dataPane.selectedIndex

  fun getData(): ByteArray {
    if (data == null) {
      return ByteArray(0)
    }
    return when (selectedIndex) {
      0 -> rawPanel.getData()
      1 -> binaryPanel.getData()
      2 -> jsonPanel.getData()
      else -> {
        err("Not effective index, though this returns raw_panel data in such case.")
        rawPanel.getData()
      }
    }
  }

  fun setData(data: ByteArray, emphasis: Range?) {
    this.data = data
    this.emphasis = emphasis
    update()
  }

  fun setData(data: ByteArray) {
    this.data = data
    emphasis = null
    update()
  }

  val parentSend: JButton?
    get() = parentSendButton

  fun setParentSend(parentSend: JButton?) {
    parentSendButton = parentSend
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  fun firePropertyChange(newValue: Any?) {
    changes.firePropertyChange(SELECTED_INDEX.toString(), null, newValue)
  }

  private fun update() {
    val currentData = data ?: return
    try {
      when (selectedIndex) {
        0 -> rawPanel.setData(currentData)
        1 -> binaryPanel.setData(currentData)
        2 ->
          jsonPanel.setData(PacketProxyUtility.getInstance().prettyFormatJSONInRawData(currentData))
        else -> err("Not effective index, though this returns raw_panel data in such case.")
      }
      val currentSearchBox = searchBox ?: return
      when (selectedIndex) {
        0 -> {
          currentSearchBox.isVisible = true
          currentSearchBox.setBaseText(rawPanel.getTextPane(), emphasis ?: Range.of(0, 0))
        }
        1 -> currentSearchBox.isVisible = false
        2 -> {
          currentSearchBox.isVisible = true
          currentSearchBox.setBaseText(jsonPanel.getTextPane(), emphasis ?: Range.of(0, 0))
        }
        else -> err("Not effective index, though this returns raw_panel data in such case.")
      }
      currentSearchBox.textChanged()
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
    firePropertyChange(selectedIndex)
  }
}
