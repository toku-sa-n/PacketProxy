package packetproxy.gui

import java.util.EventListener
import javax.swing.JButton
import javax.swing.JTextPane
import javax.swing.event.EventListenerList

abstract class GUIHistoryPanel {
  protected val listenerList = EventListenerList()

  abstract fun getTextPane(): JTextPane

  fun addDataChangedListener(listener: DataChangedListener) {
    listenerList.add(DataChangedListener::class.java, listener)
  }

  protected fun callDataChanged(data: ByteArray) {
    listenerList.getListeners(DataChangedListener::class.java).forEach { it.dataChanged(data) }
  }

  abstract fun setData(data: ByteArray)

  abstract fun getData(): ByteArray

  abstract fun setParentTabs(parentTabs: TabSet)

  abstract fun getParentSend(): JButton?

  fun interface DataChangedListener : EventListener {
    fun dataChanged(data: ByteArray)
  }
}
