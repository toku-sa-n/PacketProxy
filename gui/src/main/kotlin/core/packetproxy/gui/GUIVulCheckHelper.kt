package packetproxy.gui

import java.awt.Component
import javax.swing.*
import packetproxy.common.Range
import packetproxy.common.i18nString
import packetproxy.model.OneShotPacket
import packetproxy.vulchecker.VulChecker

class GUIVulCheckHelper(private val main: GUIMain) {
  private var mainPanel = JPanel()
  private var tabs = mutableMapOf<Component, GUIVulCheckTab>()
  private var addedTabCount = 0
  private val emptyLabel =
    emptyStateLabel(i18nString("Select text in the Request pane and right-click to run VulCheck."))
  private var vulCheckTab =
    object : CloseButtonTabbedPane() {
      override fun removeTabAt(index: Int) {
        var closed = getComponentAt(index)
        super.removeTabAt(index)
        tabs.remove(closed)
        updateEmptyState()
      }
    }

  init {
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    mainPanel.add(emptyLabel)
    mainPanel.add(vulCheckTab)
  }

  fun createPanel(): JComponent = mainPanel

  fun addVulCheck(vulChecker: VulChecker, sendPacket: OneShotPacket, range: Range) {
    onEDT {
      var tab = GUIVulCheckTab(main, vulChecker, sendPacket, range)
      var panel = tab.createPanel()
      tabs[panel] = tab
      addedTabCount++
      vulCheckTab.addTab("$addedTabCount: ${tab.checkerName}", panel)
      vulCheckTab.selectedComponent = panel
      updateEmptyState()
      main.showTab(GUIMain.Panes.VULCHECKHELPER)
    }
  }

  private fun updateEmptyState() {
    emptyLabel.setEmptyStateVisible(vulCheckTab.tabCount == 0, mainPanel)
  }
}
