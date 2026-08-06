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

import java.awt.event.KeyEvent
import java.io.File
import javax.swing.JDialog
import javax.swing.JMenu
import javax.swing.JMenuBar
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.KeyStroke
import packetproxy.common.*
import packetproxy.common.ConfigIO
import packetproxy.common.Utils
import packetproxy.util.errWithStackTrace

class GUIMenu(private val owner: GUIMain) : JMenuBar() {

  companion object {
    private val defaultDir = System.getProperty("user.home")
    private const val HEX_CALC_MIN_WIDTH = 700
    private const val HEX_CALC_MIN_HEIGHT = 140
  }

  init {
    val file_menu = JMenu(i18nString("Project"))
    this.add(file_menu)
    val save_sqlite = JMenuItem(i18nString("Save packets to sqlite3 file"), KeyEvent.VK_S)
    file_menu.add(save_sqlite)
    save_sqlite.addActionListener {
      val filechooser = WriteFileChooserWrapper(owner, "sqlite3")
      filechooser.addFileChooserListener(
        object : WriteFileChooserWrapper.FileChooserListener {

          override fun onApproved(file: File, extension: String) {
            try {
              owner.modelServices.database.Save(file.absolutePath)
              owner.modelServices.recentProjectsStore.add(file.toPath())
              JOptionPane.showMessageDialog(owner, i18nString("Data saved successfully"))
            } catch (e1: Exception) {
              errWithStackTrace(e1)
              JOptionPane.showMessageDialog(owner, i18nString("Data can't be saved with error"))
            }
          }

          override fun onCanceled() {}

          override fun onError() {
            JOptionPane.showMessageDialog(owner, i18nString("Data can't be saved with error"))
          }
        }
      )
      filechooser.showSaveDialog()
    }
    val save_txt = JMenuItem(i18nString("Save packets to text file"), KeyEvent.VK_T)
    file_menu.add(save_txt)
    save_txt.addActionListener {
      val filechooser = WriteFileChooserWrapper(owner, "txt")
      filechooser.addFileChooserListener(
        object : WriteFileChooserWrapper.FileChooserListener {

          override fun onApproved(file: File, extension: String) {
            try {
              owner.modelServices.packets.outputAllPackets(file.absolutePath)
              JOptionPane.showMessageDialog(owner, i18nString("Data saved successfully"))
            } catch (e1: Exception) {
              errWithStackTrace(e1)
              JOptionPane.showMessageDialog(owner, i18nString("Data can't be saved with error"))
            }
          }

          override fun onCanceled() {}

          override fun onError() {
            JOptionPane.showMessageDialog(owner, i18nString("Data can't be saved with error"))
          }
        }
      )
      filechooser.showSaveDialog()
    }
    val load_menu = JMenuItem(i18nString("Load packets from sqlite3 file"), KeyEvent.VK_L)
    file_menu.add(load_menu)
    load_menu.addActionListener {
      try {
        val filechooser = NativeFileChooser()
        filechooser.setCurrentDirectory(File(defaultDir))
        filechooser.addChoosableFileFilter("*.sqlite3", "sqlite3")
        filechooser.setAcceptAllFileFilterUsed(false)
        val selected = filechooser.showOpenDialog(owner)
        if (selected == NativeFileChooser.APPROVE_OPTION) {
          val file = filechooser.getSelectedFile()
          owner.modelServices.database.Load(file.absolutePath)
          owner.modelServices.recentProjectsStore.add(file.toPath())
        }
      } catch (e1: Exception) {
        errWithStackTrace(e1)
        JOptionPane.showMessageDialog(owner, i18nString("Data can't be loaded with error"))
      }
    }

    val view_menu = JMenu(i18nString("View"))
    this.add(view_menu)
    addViewMenuItem(view_menu, "View History", KeyEvent.VK_H, GUIMain.Panes.HISTORY)
    addViewMenuItem(view_menu, "View Interceptor", KeyEvent.VK_I, GUIMain.Panes.INTERCEPT)
    addViewMenuItem(view_menu, "View Resender", KeyEvent.VK_R, GUIMain.Panes.RESENDER)
    addViewMenuItem(view_menu, "View VulCheck Helper", KeyEvent.VK_V, GUIMain.Panes.VULCHECKHELPER)
    addViewMenuItem(view_menu, "View BulkSender", KeyEvent.VK_B, GUIMain.Panes.BULKSENDER)
    addViewMenuItem(view_menu, "View Extensions", KeyEvent.VK_E, GUIMain.Panes.EXTENSIONS)
    addViewMenuItem(view_menu, "View Options", KeyEvent.VK_O, GUIMain.Panes.OPTIONS)
    addViewMenuItem(view_menu, "View Log", KeyEvent.VK_L, GUIMain.Panes.LOG)

    val config_menu = JMenu(i18nString("Options"))
    this.add(config_menu)
    val import_configs = JMenuItem(i18nString("Import Configs"))
    config_menu.add(import_configs)
    import_configs.addActionListener {
      try {
        val filechooser = NativeFileChooser()
        filechooser.setCurrentDirectory(File(defaultDir))
        filechooser.addChoosableFileFilter("*.json", "json")
        filechooser.setAcceptAllFileFilterUsed(false)
        val selected = filechooser.showOpenDialog(owner)
        if (selected == NativeFileChooser.APPROVE_OPTION) {
          val file = filechooser.getSelectedFile()
          val jbytes = Utils.readfile(file.absolutePath)
          val json = String(jbytes)
          val io =
            ConfigIO(
              owner.modelServices.database,
              owner.modelServices.listenPorts,
              owner.modelServices.servers,
              owner.modelServices.modifications,
              owner.modelServices.sslPassThroughs,
            )
          io.setOptions(json)
          JOptionPane.showMessageDialog(owner, i18nString("Config loaded successfully"))
        }
      } catch (e1: Exception) {
        errWithStackTrace(e1)
        JOptionPane.showMessageDialog(owner, i18nString("Config can't be loaded with error"))
      }
    }
    val export_configs = JMenuItem(i18nString("Export Configs"))
    config_menu.add(export_configs)
    export_configs.addActionListener {
      try {
        val filechooser = WriteFileChooserWrapper(owner, "json")
        filechooser.addFileChooserListener(
          object : WriteFileChooserWrapper.FileChooserListener {

            override fun onApproved(file: File, extension: String) {
              try {
                val io =
                  ConfigIO(
                    owner.modelServices.database,
                    owner.modelServices.listenPorts,
                    owner.modelServices.servers,
                    owner.modelServices.modifications,
                    owner.modelServices.sslPassThroughs,
                  )
                val json = io.getOptions()
                Utils.writefile(file.absolutePath, json.toByteArray())
                JOptionPane.showMessageDialog(owner, i18nString("Config saved successfully"))
              } catch (e1: Exception) {
                errWithStackTrace(e1)
                JOptionPane.showMessageDialog(owner, i18nString("Config can't be saved with error"))
              }
            }

            override fun onCanceled() {}

            override fun onError() {
              JOptionPane.showMessageDialog(owner, i18nString("Config can't be saved with error"))
            }
          }
        )
        filechooser.showSaveDialog()
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }

    val tools_menu = JMenu(i18nString("Tools"))
    this.add(tools_menu)
    val decoder = JMenuItem(i18nString("Decoder"))
    tools_menu.add(decoder)
    decoder.addActionListener { showDecoderDialog() }
    val hex_calc = JMenuItem(i18nString("Hex Calculator"))
    tools_menu.add(hex_calc)
    hex_calc.addActionListener { showHexCalcDialog() }

    val help_menu = JMenu(i18nString("Help"))
    this.add(help_menu)
    val about = JMenuItem(i18nString("About PacketProxy"))
    help_menu.add(about)
    about.addActionListener { showAboutDialog() }
  }

  /** パケットのデータを貼り付けて、各種のデコード結果を確認するダイアログを開く */
  private fun showDecoderDialog() {
    try {
      GUIDecoderDialog(owner).showDialog()
    } catch (e1: Exception) {
      errWithStackTrace(e1)
    }
  }

  /** Optionsタブにもある16進数計算機を、単独のウィンドウとしても開けるようにする */
  private fun showHexCalcDialog() {
    try {
      val dialog = JDialog(owner, i18nString("Hex Calculator"), false)
      dialog.contentPane.add(GUIHexCalc().create())
      packWithMinSize(dialog, HEX_CALC_MIN_WIDTH, HEX_CALC_MIN_HEIGHT)
      dialog.centerOver(owner)
      dialog.isVisible = true
    } catch (e1: Exception) {
      errWithStackTrace(e1)
    }
  }

  private fun showAboutDialog() {
    val version = AppVersion().get()
    val message =
      listOf(
          "PacketProxy $version",
          i18nString("A local proxy tool to intercept and inspect TCP/UDP protocols."),
          "https://github.com/DeNA/PacketProxy",
        )
        .joinToString("\n")
    JOptionPane.showMessageDialog(
      owner,
      message,
      i18nString("About PacketProxy"),
      JOptionPane.INFORMATION_MESSAGE,
    )
  }

  private fun addViewMenuItem(menu: JMenu, label: String, keyCode: Int, pane: GUIMain.Panes) {
    val item = JMenuItem(i18nString(label))
    item.accelerator = KeyStroke.getKeyStroke(keyCode, viewShortcutModifiers())
    menu.add(item)
    item.addActionListener {
      try {
        owner.tabbedPane.setSelectedIndex(pane.ordinal)
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }
  }

  /** GUIMainがタブ切り替えに登録しているキーの修飾キーと同じ組み合わせを返す */
  private fun viewShortcutModifiers(): Int {
    if (owner.coreServices.packetProxyUtility.isMac()) {
      return KeyEvent.CTRL_DOWN_MASK or KeyEvent.META_DOWN_MASK
    }
    return KeyEvent.CTRL_DOWN_MASK
  }
}
