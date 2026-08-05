/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.gui

import com.formdev.flatlaf.FlatIntelliJLaf
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Insets
import java.awt.Taskbar
import java.awt.Toolkit
import java.awt.Window
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import javax.swing.AbstractAction
import javax.swing.ActionMap
import javax.swing.ImageIcon
import javax.swing.InputMap
import javax.swing.JComponent
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.JTextPane
import javax.swing.KeyStroke
import javax.swing.SwingUtilities
import javax.swing.UIManager
import javax.swing.text.DefaultEditorKit
import javax.swing.text.JTextComponent
import javax.swing.text.Keymap
import packetproxy.CoreServices
import packetproxy.common.*
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.InterceptModel
import packetproxy.model.ModelServices
import packetproxy.model.PropertyChangeEventType
import packetproxy.util.errWithStackTrace

class GUIMain(val modelServices: ModelServices, val coreServices: CoreServices) :
  JFrame(), PropertyChangeListener {

  private lateinit var menuBar: GUIMenu
  lateinit var tabbedPane: JTabbedPane
    private set

  private lateinit var guiOption: GUIOption
  private lateinit var guiHistory: GUIHistory
  private lateinit var guiIntercept: GUIIntercept
  private lateinit var guiResender: GUIResender
  private lateinit var guiBulkSender: GUIBulkSender
  private lateinit var guiExtensions: GUIExtensions
  private lateinit var guiVulCheckHelper: GUIVulCheckHelper
  private lateinit var interceptModel: InterceptModel
  private val appVersion = AppVersion()
  private val lazyTabBuilders = HashMap<Int, () -> JComponent>()
  private val initializedTabs = HashSet<Int>()

  enum class Panes {
    HISTORY,
    INTERCEPT,
    RESENDER,
    VULCHECKHELPER,
    BULKSENDER,
    EXTENSIONS,
    OPTIONS,
    LOG,
  }

  private fun getPaneString(num: Panes): String {
    return when (num) {
      Panes.HISTORY -> "History"
      Panes.INTERCEPT -> "Interceptor"
      Panes.RESENDER -> "Resender"
      Panes.VULCHECKHELPER -> "VulCheck Helper"
      Panes.BULKSENDER -> "Bulk Sender"
      Panes.EXTENSIONS -> "Extensions"
      Panes.OPTIONS -> "Options"
      Panes.LOG -> "Log"
    }
  }

  init {
    try {
      coreServices.logging.setLogSinkInternal(GuiLogSink())
      setIcon()
      guiHistory = initProjectAndHistory()
      setLookandFeel()

      // Register for database events
      modelServices.database.addPropertyChangeListener(this)

      // Set initial title with project name
      updateTitle()

      setBounds(10, 10, 1100, 850)
      enableFullScreenForMac(this)

      menuBar = GUIMenu(this)
      setJMenuBar(menuBar)

      guiOption = GUIOption(this)
      guiIntercept = GUIIntercept(this)
      guiResender = GUIResender(this)
      guiBulkSender = GUIBulkSender(this)
      guiExtensions = GUIExtensions(this, guiHistory)
      guiVulCheckHelper = GUIVulCheckHelper(this)

      tabbedPane = JTabbedPane()

      // タブの高さを数値で強制指定
      UIManager.put("TabbedPane.tabHeight", 22)
      // フォーカスが当たった時の枠線の太さを0にする
      UIManager.put("TabbedPane.focusWidth", 0)
      UIManager.put("TabbedPane.innerBorderInsets", Insets(0, 0, 0, 0))
      UIManager.put("TabbedPane.tabInsets", Insets(0, 10, 0, 10))

      SwingUtilities.updateComponentTreeUI(tabbedPane)
      tabbedPane.addTab(getPaneString(Panes.HISTORY), guiHistory.createPanel())
      initializedTabs.add(Panes.HISTORY.ordinal)
      tabbedPane.addTab(getPaneString(Panes.INTERCEPT), JPanel())
      tabbedPane.addTab(getPaneString(Panes.RESENDER), JPanel())
      tabbedPane.addTab(getPaneString(Panes.VULCHECKHELPER), JPanel())
      tabbedPane.addTab(getPaneString(Panes.BULKSENDER), JPanel())
      tabbedPane.addTab(getPaneString(Panes.EXTENSIONS), JPanel())
      tabbedPane.addTab(getPaneString(Panes.OPTIONS), JPanel())
      tabbedPane.addTab(getPaneString(Panes.LOG), JPanel())
      registerLazyTabs()
      tabbedPane.addChangeListener { initializeTab(tabbedPane.selectedIndex) }

      contentPane.add(tabbedPane, BorderLayout.CENTER)

      interceptModel = modelServices.interceptModel
      interceptModel.addPropertyChangeListener(this)

      //// 終了時の処理
      addWindowListener(
        object : WindowAdapter() {
          override fun windowClosing(event: WindowEvent) {
            System.exit(0)
          }
        }
      )
      guiHistory.updateAllAsync()
      initializeTab(Panes.INTERCEPT.ordinal)
    } catch (e: Exception) {
      errWithStackTrace(e)
      errWithStackTrace(e)
    }
  }

  fun getGuiResender(): GUIResender = guiResender

  fun getGuiHistory(): GUIHistory = guiHistory

  fun getGuiBulkSender(): GUIBulkSender = guiBulkSender

  fun getGuiVulCheckHelper(): GUIVulCheckHelper = guiVulCheckHelper

  fun getGuiExtensions(): GUIExtensions = guiExtensions

  private fun setIcon() {
    setIconForWindows()
    addDockIconForMac()
  }

  private fun initProjectAndHistory(): GUIHistory {
    val chooser = GUIProjectChooserDialog(this)
    val restore = chooser.chooseAndSetup()
    return GUIHistory(this, restore)
  }

  private fun setLookandFeel() {
    if (coreServices.packetProxyUtility.isUnix()) {
      System.setProperty("awt.useSystemAAFontSettings", "on")
      System.setProperty("swing.aatext", "true")
    }

    // FlatLaf Modern Light Theme (IntelliJ)
    try {
      FlatIntelliJLaf.setup()
    } catch (e: Exception) {
      // Fallback to Nimbus if FlatLaf fails
      for (clInfo in UIManager.getInstalledLookAndFeels()) {
        if ("Nimbus" == clInfo.name) {
          UIManager.setLookAndFeel(clInfo.className)
          break
        }
      }
    }

    // フォント設定をデフォルトに復元(シンタックスハイライト機能による影響を防ぐため)
    modelServices.fontManager.restoreUIFont()
    modelServices.fontManager.restoreFont()

    UIManager.getLookAndFeelDefaults().put("defaultFont", modelServices.fontManager.getUIFont())
    // OptionPaneのロケール
    JOptionPane.setDefaultLocale(i18nLocale)

    // スクロールバーの幅を太くする
    UIManager.put("ScrollBar.width", 15)

    addShortcutForWindows()
    addShortcutForMac()
  }

  /** Windowsにアイコンを表示する */
  private fun setIconForWindows() {
    if (!coreServices.packetProxyUtility.isWindows()) {
      return
    }
    val icon = ImageIcon(javaClass.getResource("/gui/icon.png"))
    iconImage = icon.image
  }

  /** MacのDock上でにPacketProxyアイコンを表示する */
  private fun addDockIconForMac() {
    if (!coreServices.packetProxyUtility.isMac()) {
      return
    }
    val icon = ImageIcon(javaClass.getResource("/gui/icon.png"))
    Taskbar.getTaskbar().iconImage = icon.image
  }

  /** JTextPane上でCommand+Cとかでコピペをできるようにする */
  private fun addShortcutForMac() {
    if (!coreServices.packetProxyUtility.isMac()) {
      return
    }
    val p = contentPane as JPanel
    val im = p.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
    val am = p.actionMap
    val hotkey = KeyEvent.CTRL_MASK or KeyEvent.META_MASK
    registerTabShortcut(KeyEvent.VK_H, hotkey, im, am, Panes.HISTORY.ordinal)
    registerTabShortcut(KeyEvent.VK_I, hotkey, im, am, Panes.INTERCEPT.ordinal)
    registerTabShortcut(KeyEvent.VK_R, hotkey, im, am, Panes.RESENDER.ordinal)
    registerTabShortcut(KeyEvent.VK_B, hotkey, im, am, Panes.BULKSENDER.ordinal)
    registerTabShortcut(KeyEvent.VK_O, hotkey, im, am, Panes.OPTIONS.ordinal)
    registerTabShortcut(KeyEvent.VK_L, hotkey, im, am, Panes.LOG.ordinal)

    val bindings1 =
      arrayOf(
        JTextComponent.KeyBinding(
          KeyStroke.getKeyStroke(KeyEvent.VK_C, Toolkit.getDefaultToolkit().menuShortcutKeyMask),
          DefaultEditorKit.copyAction,
        ),
        JTextComponent.KeyBinding(
          KeyStroke.getKeyStroke(KeyEvent.VK_V, Toolkit.getDefaultToolkit().menuShortcutKeyMask),
          DefaultEditorKit.pasteAction,
        ),
        JTextComponent.KeyBinding(
          KeyStroke.getKeyStroke(KeyEvent.VK_X, Toolkit.getDefaultToolkit().menuShortcutKeyMask),
          DefaultEditorKit.cutAction,
        ),
        JTextComponent.KeyBinding(
          KeyStroke.getKeyStroke(KeyEvent.VK_A, Toolkit.getDefaultToolkit().menuShortcutKeyMask),
          DefaultEditorKit.selectAllAction,
        ),
      )

    val componentTp = JTextPane()
    val keymapTp: Keymap = componentTp.keymap
    JTextComponent.loadKeymap(keymapTp, bindings1, componentTp.actions)

    val componentTf = JTextField()
    val keymapTf: Keymap = componentTf.keymap
    JTextComponent.loadKeymap(keymapTf, bindings1, componentTf.actions)

    val componentTa = JTextArea()
    val keymapTa: Keymap = componentTa.keymap
    JTextComponent.loadKeymap(keymapTa, bindings1, componentTa.actions)
  }

  private fun addShortcutForWindows() {
    if (coreServices.packetProxyUtility.isMac()) {
      return
    }
    val p = contentPane as JPanel
    val im = p.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
    val am = p.actionMap
    val hotkey = KeyEvent.CTRL_MASK
    registerTabShortcut(KeyEvent.VK_H, hotkey, im, am, Panes.HISTORY.ordinal)
    registerTabShortcut(KeyEvent.VK_I, hotkey, im, am, Panes.INTERCEPT.ordinal)
    registerTabShortcut(KeyEvent.VK_R, hotkey, im, am, Panes.RESENDER.ordinal)
    registerTabShortcut(KeyEvent.VK_B, hotkey, im, am, Panes.BULKSENDER.ordinal)
    registerTabShortcut(KeyEvent.VK_O, hotkey, im, am, Panes.OPTIONS.ordinal)
    registerTabShortcut(KeyEvent.VK_L, hotkey, im, am, Panes.LOG.ordinal)
  }

  private fun registerTabShortcut(k: Int, m: Int, im: InputMap, am: ActionMap, index: Int) {
    val ks = KeyStroke.getKeyStroke(k, m)
    im.put(ks, ks.toString())
    am.put(
      ks.toString(),
      object : AbstractAction() {
        override fun actionPerformed(arg0: ActionEvent) {
          tabbedPane.selectedIndex = index
        }
      },
    )
  }

  /** Macでフルスクリーン表示できるようにする */
  private fun enableFullScreenForMac(window: Window) {
    if (!coreServices.packetProxyUtility.isMac()) {
      return
    }
    rootPane.putClientProperty("apple.awt.fullscreenable", true)
  }

  // Nimbusのバグでjava1.6系列ではsetForegroundAt, setBackgroundAtが効かない
  // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6939001
  private fun setInterceptHighLight() {
    val label = JLabel(tabbedPane.getTitleAt(1))
    label.foreground = Color(255, 180, 0) // Bright orange for dark theme
    tabbedPane.setTabComponentAt(1, label)
    tabbedPane.revalidate()
    tabbedPane.repaint()
  }

  private fun setInterceptDownLight() {
    val label = JLabel(tabbedPane.getTitleAt(1))
    // Use default foreground color from Look and Feel
    label.foreground = UIManager.getColor("TabbedPane.foreground")
    tabbedPane.setTabComponentAt(1, label)
    tabbedPane.revalidate()
    tabbedPane.repaint()
  }

  fun updateTitle() {
    val titleText =
      String.format("PacketProxy %s - %s", appVersion.get(), get(modelServices.database))
    title = titleText
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (PropertyChangeEventType.INTERCEPT_DATA.matches(evt)) {
      if (evt.newValue == null) {
        setInterceptDownLight()
      } else {
        setInterceptHighLight()
      }
    } else if (PropertyChangeEventType.DATABASE_MESSAGE.matches(evt)) {
      if (evt.newValue is DatabaseMessage) {
        val msg = evt.newValue as DatabaseMessage
        if (msg == DatabaseMessage.RECONNECT) {
          SwingUtilities.invokeLater { updateTitle() }
        }
      }
    }
  }

  companion object {
    private val serialVersionUID = 1L
  }

  private fun registerLazyTabs() {
    lazyTabBuilders[Panes.INTERCEPT.ordinal] = { guiIntercept.createPanel() }
    lazyTabBuilders[Panes.RESENDER.ordinal] = { guiResender.createPanel() }
    lazyTabBuilders[Panes.VULCHECKHELPER.ordinal] = { guiVulCheckHelper.createPanel() }
    lazyTabBuilders[Panes.BULKSENDER.ordinal] = { guiBulkSender.createPanel() }
    lazyTabBuilders[Panes.EXTENSIONS.ordinal] = { guiExtensions.createPanel() }
    lazyTabBuilders[Panes.OPTIONS.ordinal] = { guiOption.createPanel() }
    lazyTabBuilders[Panes.LOG.ordinal] = { coreServices.logging.createLogPanelInternal() }
  }

  private fun initializeTab(index: Int) {
    if (initializedTabs.contains(index)) {
      return
    }
    val builder = lazyTabBuilders[index] ?: return
    tabbedPane.setComponentAt(index, builder())
    initializedTabs.add(index)
  }
}
