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

import java.awt.Dimension
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import packetproxy.common.DialogParents

open class JWTHeaderRS256toHS256Generator : Generator() {
  override fun getName(): String = "Header: alg: RS256 -> HS256"

  override fun generateOnStart(): Boolean = false

  private var cancelClicked = false

  @Throws(Exception::class)
  override fun generate(inputData: String): String {
    cancelClicked = false
    val dlg = JDialog(DialogParents.mainFrame)

    val rect = DialogParents.mainFrame!!.bounds
    val width = 400
    val height = 300
    dlg.setBounds(
      rect.x + rect.width / 2 - width / 2,
      rect.y + rect.height / 2 - height / 2,
      width,
      height,
    ) /* ド真ん中 */

    val labels = JPanel()
    labels.layout = BoxLayout(labels, BoxLayout.X_AXIS)
    labels.add(JLabel("RSA Public Key?"))
    labels.maximumSize = Dimension(Short.MAX_VALUE.toInt(), labels.maximumSize.height)

    val area = JTextArea()
    val scrollpane = JScrollPane(area)
    scrollpane.maximumSize = Dimension(Short.MAX_VALUE.toInt(), scrollpane.maximumSize.height)

    val buttons = JPanel()
    buttons.layout = BoxLayout(buttons, BoxLayout.X_AXIS)
    val ok = JButton("設定")
    ok.addMouseListener(
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          super.mouseClicked(e)
          dlg.dispose()
        }
      }
    )
    buttons.add(ok)
    val cancel = JButton("キャンセル")
    cancel.addMouseListener(
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          super.mouseClicked(e)
          cancelClicked = true
          dlg.dispose()
        }
      }
    )
    buttons.add(cancel)

    val main = JPanel()
    main.layout = BoxLayout(main, BoxLayout.Y_AXIS)
    main.add(labels)
    main.add(scrollpane)
    main.add(buttons)
    dlg.contentPane.add(main)
    dlg.isModal = true
    dlg.isVisible = true

    if (cancelClicked) {
      throw Exception("cancel")
    }

    val pubkey = area.text
    val jwt = JWTAlgHS256(inputData, pubkey)
    jwt.setHeaderValue("alg", "HS256")
    return jwt.toJwtString()
  }
}
