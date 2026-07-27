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
import javax.swing.JFrame
import javax.swing.JMenu
import javax.swing.JMenuBar
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import packetproxy.common.ConfigIO
import packetproxy.common.I18nString
import packetproxy.common.RecentProjectsStore
import packetproxy.common.Utils
import packetproxy.model.Database
import packetproxy.model.Packets
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.PacketProxyUtility

class GUIMenu(private val owner: JFrame) : JMenuBar() {

  private enum class Panes {
    HISTORY,
    INTERCEPT,
    RESENDER,
    BULKSENDER,
    OPTIONS,
    LOG,
  }

  companion object {
    private val defaultDir = System.getProperty("user.home")
  }

  init {
    val file_menu = JMenu(I18nString.get("Project"))
    this.add(file_menu)
    val save_sqlite = JMenuItem(I18nString.get("Save packets to sqlite3 file"), KeyEvent.VK_S)
    file_menu.add(save_sqlite)
    save_sqlite.addActionListener {
      val filechooser = WriteFileChooserWrapper(owner, "sqlite3")
      filechooser.addFileChooserListener(
        object : WriteFileChooserWrapper.FileChooserListener {

          override fun onApproved(file: File, extension: String) {
            try {
              Database.getInstance().Save(file.absolutePath)
              RecentProjectsStore.add(file.toPath())
              JOptionPane.showMessageDialog(null, I18nString.get("Data saved successfully"))
            } catch (e1: Exception) {
              errWithStackTrace(e1)
              JOptionPane.showMessageDialog(null, I18nString.get("Data can't be saved with error"))
            }
          }

          override fun onCanceled() {}

          override fun onError() {
            JOptionPane.showMessageDialog(null, I18nString.get("Data can't be saved with error"))
          }
        }
      )
      filechooser.showSaveDialog()
    }
    val save_txt = JMenuItem(I18nString.get("Save packets to text file"), KeyEvent.VK_S)
    file_menu.add(save_txt)
    save_txt.addActionListener {
      val filechooser = WriteFileChooserWrapper(owner, "txt")
      filechooser.addFileChooserListener(
        object : WriteFileChooserWrapper.FileChooserListener {

          override fun onApproved(file: File, extension: String) {
            try {
              Packets.getInstance().outputAllPackets(file.absolutePath)
              JOptionPane.showMessageDialog(null, I18nString.get("Data saved successfully"))
            } catch (e1: Exception) {
              errWithStackTrace(e1)
              JOptionPane.showMessageDialog(null, I18nString.get("Data can't be saved with error"))
            }
          }

          override fun onCanceled() {}

          override fun onError() {
            JOptionPane.showMessageDialog(null, I18nString.get("Data can't be saved with error"))
          }
        }
      )
      filechooser.showSaveDialog()
    }
    val load_menu = JMenuItem(I18nString.get("Load packets from sqlite3 file"), KeyEvent.VK_L)
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
          Database.getInstance().Load(file.absolutePath)
          RecentProjectsStore.add(file.toPath())
        }
      } catch (e1: Exception) {
        errWithStackTrace(e1)
        JOptionPane.showMessageDialog(null, I18nString.get("Data can't be loaded with error"))
      }
    }

    var cmd_key = "⌘ ^ "
    if (!PacketProxyUtility.getInstance().isMac()) {
      cmd_key = "Ctrl + "
    }
    val view_menu = JMenu(I18nString.get("View"))
    this.add(view_menu)
    val view_history = JMenuItem(I18nString.get("View History") + "  " + cmd_key + "H")
    view_menu.add(view_history)
    view_history.addActionListener {
      try {
        GUIMain.getInstance().tabbedPane.setSelectedIndex(Panes.HISTORY.ordinal)
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }
    val view_intercept = JMenuItem(I18nString.get("View Interceptor") + "  " + cmd_key + "I")
    view_menu.add(view_intercept)
    view_intercept.addActionListener {
      try {
        GUIMain.getInstance().tabbedPane.setSelectedIndex(Panes.INTERCEPT.ordinal)
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }
    val view_resender = JMenuItem(I18nString.get("View Resender") + "  " + cmd_key + "R")
    view_menu.add(view_resender)
    view_resender.addActionListener {
      try {
        GUIMain.getInstance().tabbedPane.setSelectedIndex(Panes.RESENDER.ordinal)
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }
    val view_bulk_sender = JMenuItem(I18nString.get("View BulkSender") + "  " + cmd_key + "B")
    view_menu.add(view_bulk_sender)
    view_bulk_sender.addActionListener {
      try {
        GUIMain.getInstance().tabbedPane.setSelectedIndex(Panes.BULKSENDER.ordinal)
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }
    val view_options = JMenuItem(I18nString.get("View Options") + "  " + cmd_key + "O")
    view_menu.add(view_options)
    view_options.addActionListener {
      try {
        GUIMain.getInstance().tabbedPane.setSelectedIndex(Panes.OPTIONS.ordinal)
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }
    val view_log = JMenuItem(I18nString.get("View Log") + "  " + cmd_key + "L")
    view_menu.add(view_log)
    view_log.addActionListener {
      try {
        GUIMain.getInstance().tabbedPane.setSelectedIndex(Panes.LOG.ordinal)
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }

    val config_menu = JMenu(I18nString.get("Options"))
    this.add(config_menu)
    val import_configs = JMenuItem(I18nString.get("Import Configs"))
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
          val io = ConfigIO()
          io.setOptions(json)
          JOptionPane.showMessageDialog(null, I18nString.get("Config loaded successfully"))
        }
      } catch (e1: Exception) {
        errWithStackTrace(e1)
        JOptionPane.showMessageDialog(null, I18nString.get("Config can't be loaded with error"))
      }
    }
    val export_configs = JMenuItem(I18nString.get("Export Configs"))
    config_menu.add(export_configs)
    export_configs.addActionListener {
      try {
        val filechooser = WriteFileChooserWrapper(owner, "json")
        filechooser.addFileChooserListener(
          object : WriteFileChooserWrapper.FileChooserListener {

            override fun onApproved(file: File, extension: String) {
              try {
                val io = ConfigIO()
                val json = io.getOptions()
                Utils.writefile(file.absolutePath, json.toByteArray())
                JOptionPane.showMessageDialog(null, I18nString.get("Config saved successfully"))
              } catch (e1: Exception) {
                errWithStackTrace(e1)
                JOptionPane.showMessageDialog(
                  null,
                  I18nString.get("Config can't be saved with error"),
                )
              }
            }

            override fun onCanceled() {}

            override fun onError() {
              JOptionPane.showMessageDialog(
                null,
                I18nString.get("Config can't be saved with error"),
              )
            }
          }
        )
        filechooser.showSaveDialog()
      } catch (e1: Exception) {
        errWithStackTrace(e1)
      }
    }
  }
}
