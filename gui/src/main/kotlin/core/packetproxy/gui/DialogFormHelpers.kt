/*
 * Copyright 2026 DeNA Co., Ltd.
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

import java.awt.Component
import java.awt.Dimension
import java.awt.event.KeyEvent
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.KeyStroke

// 設定ダイアログのフォームを組み立てるための共通部品。

/** ラベルと入力部品を横に並べた1行を作る。ラベル幅を揃えることで行ごとの入力欄の左端が揃う。 */
internal fun labeledRow(label: String, component: JComponent, labelWidth: Int = 150): JComponent {
  var row = JPanel()
  row.layout = BoxLayout(row, BoxLayout.X_AXIS)
  row.alignmentX = Component.LEFT_ALIGNMENT
  var labelComponent = JLabel(label)
  labelComponent.preferredSize = Dimension(labelWidth, labelComponent.maximumSize.height)
  row.add(labelComponent)
  component.maximumSize = Dimension(Short.MAX_VALUE.toInt(), labelComponent.maximumSize.height * 2)
  row.add(component)
  return row
}

/** 保存ボタンをEnter、キャンセルをEscに割り当て、それぞれの処理を登録する。 */
internal fun installDefaultActions(
  dialog: JDialog,
  saveButton: JButton,
  cancelButton: JButton,
  onSave: () -> Unit,
  onCancel: () -> Unit,
) {
  saveButton.addActionListener { onSave() }
  cancelButton.addActionListener { onCancel() }
  dialog.rootPane.defaultButton = saveButton
  dialog.rootPane.registerKeyboardAction(
    { onCancel() },
    KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
    JComponent.WHEN_IN_FOCUSED_WINDOW,
  )
}

/** 呼び出し元のウィンドウの中央にダイアログを配置する。表示されていない場合は画面中央に置く。 */
internal fun JDialog.centerOver(owner: Component?) {
  setLocationRelativeTo(owner)
}

/** 中身に合わせた大きさにしつつ、最低限の大きさを下回らないようにする。 */
internal fun packWithMinSize(dialog: JDialog, minWidth: Int, minHeight: Int) {
  dialog.pack()
  dialog.minimumSize = Dimension(minWidth, minHeight)
  dialog.setSize(maxOf(dialog.width, minWidth), maxOf(dialog.height, minHeight))
}
