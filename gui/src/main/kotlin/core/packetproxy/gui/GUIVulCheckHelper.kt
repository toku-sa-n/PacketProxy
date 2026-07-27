package packetproxy.gui

import javax.swing.*
import javax.swing.event.ChangeListener
import packetproxy.common.Range
import packetproxy.model.OneShotPacket
import packetproxy.vulchecker.VulChecker

class GUIVulCheckHelper private constructor() {
  private var mainPanel = JPanel()
  private var vulCheckTab = CloseButtonTabbedPane()
  private var list = mutableListOf<GUIVulCheckTab>()
  private var previousTabIndex = vulCheckTab.selectedIndex

  init {
    vulCheckTab.addChangeListener(
      ChangeListener {
        var current = vulCheckTab.selectedIndex
        if (previousTabIndex < 0) {
          previousTabIndex = current
          return@ChangeListener
        }
        previousTabIndex = current
      }
    )
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    mainPanel.add(vulCheckTab)
  }

  fun createPanel(): JComponent = mainPanel

  fun addVulCheck(vulChecker: VulChecker, sendPacket: OneShotPacket, range: Range) {
    var tab = GUIVulCheckTab(vulChecker, sendPacket, range)
    var panel = tab.createPanel()
    list.add(tab)
    vulCheckTab.addTab(list.size.toString(), panel)
    vulCheckTab.selectedComponent = panel
  }

  companion object {
    private var instance: GUIVulCheckHelper? = null

    @JvmStatic
    fun getInstance(): GUIVulCheckHelper = instance ?: GUIVulCheckHelper().also { instance = it }
  }
}
