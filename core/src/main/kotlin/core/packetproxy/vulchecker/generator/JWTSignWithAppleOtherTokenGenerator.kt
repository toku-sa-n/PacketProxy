/*
 * Copyright 2023 DeNA Co., Ltd.
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
package packetproxy.vulchecker.generator

import java.awt.Desktop
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.net.URI
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import packetproxy.common.DialogParents
import packetproxy.common.TokenHttpServer
import packetproxy.util.Logging.errWithStackTrace

open class JWTSignWithAppleOtherTokenGenerator : Generator() {
  override fun getName(): String = "他サービスのApple id_tokenと入れ替え"

  override fun generateOnStart(): Boolean = false

  private var tokenFromBrowser: String = ""
  private var cancelClicked = false
  private var server: TokenHttpServer? = null

  @Throws(Exception::class)
  override fun generate(inputData: String): String {
    this.tokenFromBrowser = ""
    this.cancelClicked = false

    val dlg = JDialog(DialogParents.mainFrame)

    val rect = DialogParents.mainFrame!!.bounds
    val width = 300
    val height = 150
    dlg.setBounds(
      rect.x + rect.width / 2 - width / 2,
      rect.y + rect.height / 2 - height / 2,
      width,
      height,
    ) /* ド真ん中 */

    val labels = JPanel()
    labels.layout = BoxLayout(labels, BoxLayout.X_AXIS)
    val label = JLabel("ブラウザに遷移してSign In with Appleします")
    label.maximumSize = Dimension(Short.MAX_VALUE.toInt(), 100)
    label.horizontalAlignment = JLabel.CENTER
    label.verticalTextPosition = JLabel.CENTER
    labels.add(label)
    labels.maximumSize = Dimension(Short.MAX_VALUE.toInt(), labels.maximumSize.height)

    val buttons = JPanel()
    buttons.layout = FlowLayout()
    val ok = JButton("ブラウザに遷移")
    ok.addMouseListener(
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val desktop = Desktop.getDesktop()
            desktop.browse(URI("https://token.funacs.com/apple"))
          } catch (e1: Exception) {
            errWithStackTrace(e1)
          }
        }
      }
    )
    buttons.add(ok)
    val cancel = JButton("キャンセル")
    cancel.addMouseListener(
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          cancelClicked = true
          dlg.dispose()
        }
      }
    )
    buttons.add(cancel)
    buttons.maximumSize = Dimension(Short.MAX_VALUE.toInt(), 50)

    if (server == null) {
      server =
        TokenHttpServer("localhost", 32350) { token ->
          tokenFromBrowser = token
          dlg.dispose()
        }
    }
    server!!.start()

    val main = JPanel()
    main.layout = BoxLayout(main, BoxLayout.Y_AXIS)
    main.add(labels)
    main.add(buttons)
    dlg.contentPane.add(main)
    dlg.isModal = true
    dlg.isVisible = true

    if (cancelClicked) {
      throw Exception("cancel")
    }

    DialogParents.mainFrame!!.isAlwaysOnTop = true
    DialogParents.mainFrame!!.isVisible = true

    // Need to wait for the server to finish sending the response data before
    // exiting
    Thread.sleep(100)
    server!!.stop()

    DialogParents.mainFrame!!.isAlwaysOnTop = false

    return tokenFromBrowser
  }
}
