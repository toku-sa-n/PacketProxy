package packetproxy.gui

import java.awt.Component
import java.awt.Dimension
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import javax.swing.*
import packetproxy.common.i18nString
import packetproxy.controller.InterceptController
import packetproxy.util.errWithStackTrace

class GUIIntercept(private val owner: GUIMain) : PropertyChangeListener {
  private val controller = owner.coreServices.interceptController
  private var model = owner.modelServices.interceptModel
  private lateinit var forward: JButton
  private lateinit var forwardMultiple: JButton
  private lateinit var drop: JButton
  private lateinit var enabled: JToggleButton
  private lateinit var stateLabel: JLabel
  private lateinit var tabs: TabSet
  private lateinit var serverNamePanel: GUIServerNamePanel
  private lateinit var packetPanel: JComponent
  private lateinit var mainPanel: JPanel
  private val emptyLabel =
    emptyStateLabel(i18nString("No packet is waiting. Turn intercept on to capture a packet."))
  private var rawOriginal = ByteArray(0)
  private var original = ByteArray(0)

  init {
    model.addPropertyChangeListener(this)
  }

  fun createPanel(): JComponent {
    enabled =
      JToggleButton(i18nString("Intercept")).apply {
        toolTipText = i18nString("Turn intercept mode on/off (Space)")
        addActionListener {
          if (isSelected) controller.enableInterceptMode()
          else controller.disableInterceptMode(interceptData)
        }
      }
    stateLabel = JLabel(i18nString("Intercept OFF")).apply { foreground = stateColor(false) }
    forward =
      JButton(i18nString("forward")).apply {
        isEnabled = false
        toolTipText = i18nString("Forward this packet (Enter)")
        addActionListener {
          try {
            controller.forward(interceptData)
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    forwardMultiple =
      JButton(i18nString("forward x N...")).apply {
        isEnabled = false
        toolTipText = i18nString("Forward this packet and resend it the specified number of times")
        addActionListener { forwardMultipleWithCount() }
      }
    drop =
      JButton(i18nString("drop")).apply {
        isEnabled = false
        toolTipText = i18nString("Drop this packet (Esc)")
        addActionListener {
          try {
            controller.drop()
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      }
    serverNamePanel = GUIServerNamePanel()
    tabs = TabSet(owner, true, false)
    packetPanel = createPacketPanel()
    mainPanel =
      JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        add(createButtonPanel())
        add(emptyLabel)
        add(packetPanel)
        registerShortcuts(this)
      }
    updateEmptyState(false)
    return mainPanel
  }

  fun dispose() {
    model.removePropertyChangeListener(this)
  }

  override fun propertyChange(event: PropertyChangeEvent) {
    onEDT { updateUiFromModel() }
  }

  private fun createButtonPanel(): JComponent {
    var interceptRules =
      JButton(i18nString("Intercept Rules...")).apply {
        toolTipText = i18nString("Open the intercept rules in the Options tab")
        addActionListener { owner.showOptionCategory(i18nString("Intercept Rules")) }
      }
    return JPanel().apply {
      add(enabled)
      add(stateLabel)
      add(forward)
      add(forwardMultiple)
      add(drop)
      add(interceptRules)
      maximumSize = Dimension(Short.MAX_VALUE.toInt(), preferredSize.height)
      alignmentX = Component.CENTER_ALIGNMENT
    }
  }

  private fun createPacketPanel(): JComponent =
    JPanel().apply {
      layout = BoxLayout(this, BoxLayout.Y_AXIS)
      add(serverNamePanel)
      add(tabs.tabPanel)
    }

  /** Enter/Esc/Space をパネル配下のフォーカスに対して有効にする。テキスト編集中は JTextPane 自身のキーバインドが 優先されるため、編集操作は妨げられない。 */
  private fun registerShortcuts(panel: JComponent) {
    var inputMap = panel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
    var actionMap = panel.actionMap
    bind(inputMap, actionMap, KeyEvent.VK_ENTER, ACTION_FORWARD) { forward.doClick() }
    bind(inputMap, actionMap, KeyEvent.VK_ESCAPE, ACTION_DROP) { drop.doClick() }
    bind(inputMap, actionMap, KeyEvent.VK_SPACE, ACTION_TOGGLE) { enabled.doClick() }
  }

  private fun bind(
    inputMap: InputMap,
    actionMap: ActionMap,
    keyCode: Int,
    name: String,
    action: () -> Unit,
  ) {
    inputMap.put(KeyStroke.getKeyStroke(keyCode, 0), name)
    actionMap.put(
      name,
      object : AbstractAction() {
        override fun actionPerformed(event: ActionEvent) {
          try {
            action()
          } catch (e: Exception) {
            errWithStackTrace(e)
          }
        }
      },
    )
  }

  private fun forwardMultipleWithCount() {
    try {
      var defaultCount = InterceptController.DEFAULT_FORWARD_MULTIPLE_COUNT
      var count = askSendCount(owner, defaultCount) ?: return
      controller.forwardMultiple(interceptData, count)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private val interceptData: ByteArray
    get() =
      when (tabs.selectedIndex) {
        0 -> if (rawOriginal.contentEquals(tabs.raw.getData())) original else tabs.raw.getData()
        1 -> tabs.binary.getData()
        2 -> tabs.json.getData()
        /* HTTP構造化タブは読み取り専用なので、受信したパケットをそのまま流す */
        else -> original
      }

  private fun updateUiFromModel() {
    try {
      var interceptEnabled = model.isInterceptEnabled()
      enabled.isSelected = interceptEnabled
      var stateText = if (interceptEnabled) "Intercept ON" else "Intercept OFF"
      stateLabel.text = i18nString(stateText)
      stateLabel.foreground = stateColor(interceptEnabled)
      var client = model.getClientPacket()
      var server = model.getServerPacket()
      var waiting = client != null || server != null
      forward.isEnabled = waiting
      forwardMultiple.isEnabled = waiting
      drop.isEnabled = waiting
      updateEmptyState(waiting)
      if (!waiting) {
        clearPacket()
        return
      }
      var data = model.getData() ?: ByteArray(0)
      serverNamePanel.updateServerName(client, server)
      tabs.setData(data)
      rawOriginal = tabs.raw.getData()
      original = data
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun clearPacket() {
    serverNamePanel.updateServerName(null, null)
    tabs.setData(ByteArray(0))
    rawOriginal = ByteArray(0)
    original = ByteArray(0)
  }

  private fun updateEmptyState(waiting: Boolean) {
    if (!::mainPanel.isInitialized) return
    packetPanel.isVisible = waiting
    emptyLabel.setEmptyStateVisible(!waiting, mainPanel)
  }

  private fun stateColor(interceptEnabled: Boolean) =
    if (interceptEnabled) ThemeColors.emphasisForeground() else ThemeColors.secondaryForeground()

  companion object {
    private const val ACTION_FORWARD = "packetproxy.intercept.forward"
    private const val ACTION_DROP = "packetproxy.intercept.drop"
    private const val ACTION_TOGGLE = "packetproxy.intercept.toggle"
  }
}
