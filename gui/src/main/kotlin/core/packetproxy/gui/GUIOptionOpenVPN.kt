package packetproxy.gui

import java.awt.event.MouseAdapter
import javax.swing.*
import packetproxy.OpenVPN
import packetproxy.model.ConfigBoolean
import packetproxy.model.OpenVPNForwardPort
import packetproxy.model.OpenVPNForwardPorts
import packetproxy.util.Logging.errWithStackTrace

class GUIOptionOpenVPN(owner: JFrame) : GUIOptionComponentBase<OpenVPNForwardPort>(owner) {
  private val forwardPorts = OpenVPNForwardPorts.getInstance()
  private val tableList = mutableListOf<OpenVPNForwardPort>()
  private val checkBox = JCheckBox("Use OpenVPN")
  private val base = JPanel()
  private val openVPN = OpenVPN.getInstance()

  init {
    forwardPorts.addPropertyChangeListener(this)
    jcomponent =
      createComponent(
        arrayOf("Proto", "src port", "dst port"),
        intArrayOf(80, 80, 80),
        object : MouseAdapter() {},
        { GUIOptionOpenVPNDialog(owner).showDialog()?.let(forwardPorts::create) },
        {
          val old = getSelectedTableContent()
          GUIOptionOpenVPNDialog(owner).showDialog(old)?.let {
            forwardPorts.delete(old)
            forwardPorts.create(it)
          }
        },
        { forwardPorts.delete(getSelectedTableContent()) },
      )
    updateImpl()
    base.add(checkBox)
    base.add(createPanel())
    checkBox.addActionListener {
      if (checkBox.isSelected) openVPN.startServer(spoofingIP, "UDP") else openVPN.stopServer()
    }
    updateState()
  }

  fun getPanel() = base

  fun isAutoSpoofing() = true

  val spoofingIP
    get() = "127.0.0.1"

  fun updateState() {
    try {
      checkBox.isSelected = ConfigBoolean("OpenVPN").getState()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun addTableContent(value: OpenVPNForwardPort) {
    tableList.add(value)
    option_model.addRow(arrayOf<Any?>(value.getType(), value.getFromPort(), value.getToPort()))
  }

  override fun updateTable(values: List<OpenVPNForwardPort>) {
    clearTableContents()
    values.forEach(::addTableContent)
  }

  override fun updateImpl() {
    try {
      updateTable(forwardPorts.queryAll())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    tableList.clear()
  }

  override fun getSelectedTableContent() = getTableContent(table.selectedRow)

  override fun getTableContent(rowIndex: Int) = tableList[rowIndex]
}
