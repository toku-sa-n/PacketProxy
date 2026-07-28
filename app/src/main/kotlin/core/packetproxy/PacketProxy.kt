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
package packetproxy

import java.io.File
import java.sql.SQLException
import javax.swing.JOptionPane
import packetproxy.common.*
import packetproxy.common.Utils
import packetproxy.gui.GUIMain
import packetproxy.gui.Splash
import packetproxy.gulp.GulpTerminal
import packetproxy.util.Logging

class PacketProxy(private val app: AppInitializer) {
  @JvmField var gui: GUIMain? = null
  @JvmField var listenPortManager: ListenPortManager? = null

  @Throws(Exception::class)
  fun start() {
    startGUI()
    app.initComponents()
  }

  @Throws(Exception::class)
  private fun startGUI() {
    gui = GUIMain(app.requireModelServices(), app.requireCoreServices())
    gui!!.isVisible = true
  }

  companion object {
    @JvmStatic
    @Throws(Exception::class)
    fun main(args: Array<String>) {
      val gulpMode = getOption("--gulp", args)
      val settingsJson = getOption("--settings-json", args)
      val app = AppInitializer.bootstrap()
      app.setArgs(gulpMode != null, settingsJson)
      app.initCore()

      if (gulpMode != null) {
        try {
          app.createModelServices(null, false)
          app.initGulp()
          app.initComponents()
        } catch (e: Exception) {
          Logging.errWithStackTrace(e)
          System.exit(1)
        }

        Logging.log("Gulp Mode: $settingsJson")
        GulpTerminal()
          .run(app.requireModelServices(), app.requireCoreServices(), settingsJson, gulpMode)
        System.exit(0)
      }

      if (!Utils.supportedJava()) {
        JOptionPane.showMessageDialog(
          null,
          i18nString("PacketProxy can be executed with JDK17 or later"),
          i18nString("Error"),
          JOptionPane.ERROR_MESSAGE,
        )
        return
      }

      val splash = Splash()
      splash.show()
      app.createModelServices(null, true)

      while (true) {
        try {
          val proxy = PacketProxy(app)
          proxy.start()
        } catch (e: SQLException) {
          val option =
            JOptionPane.showConfirmDialog(
              null,
              i18nString("Database read error.\nDelete the database and reboot?"),
              i18nString("Database error"),
              JOptionPane.YES_NO_OPTION,
              JOptionPane.WARNING_MESSAGE,
            )
          if (option == JOptionPane.YES_OPTION) {
            try {
              val resource =
                File(System.getProperty("user.home"), ".packetproxy/db/resources.sqlite3")
              if (resource.exists()) {
                resource.delete()
              }
              app.switchProject(resource.absolutePath)
            } catch (e2: Exception) {
              Logging.errWithStackTrace(e2)
            }
            continue
          }
        } catch (e: Exception) {
          Logging.errWithStackTrace(e)
        }
        break
      }
      splash.close()
    }

    /**
     * バイナリに渡される引数を解釈する
     *
     * @param option 取得したいオプションの文字列（末尾に=を含まない）
     * @param args 対象の引数の配列
     * @return 存在しない場合はnull, 存在する場合、最初の出現に対しての=以降の文字列（=が含まれない場合や=以降が存在しない場合は空文字）
     */
    private fun getOption(option: String, args: Array<String>): String? {
      val addedOption = "$option="
      for (arg in args) {
        if (arg == option) return ""
        if (arg.startsWith(addedOption)) return arg.substring(addedOption.length)
      }
      return null
    }
  }
}
