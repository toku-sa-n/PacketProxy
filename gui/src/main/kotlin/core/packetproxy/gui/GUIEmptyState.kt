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
import javax.swing.BorderFactory
import javax.swing.JLabel
import javax.swing.SwingConstants

/** 表やタブが空のときに、次に何をすれば良いかを案内するラベルを作る。 */
internal fun emptyStateLabel(text: String): JLabel {
  var label = JLabel(text, SwingConstants.CENTER)
  label.alignmentX = Component.CENTER_ALIGNMENT
  label.foreground = ThemeColors.secondaryForeground()
  label.border = BorderFactory.createEmptyBorder(8, 12, 8, 12)
  // BoxLayoutで縦に伸びてテーブルの領域を奪わないよう高さを固定する
  label.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.preferredSize.height)
  return label
}

/** 空状態ラベルの表示状態を切り替える。切り替えが起きたときだけ再レイアウトする。 */
internal fun JLabel.setEmptyStateVisible(empty: Boolean, container: Component) {
  if (isVisible == empty) {
    return
  }
  isVisible = empty
  container.revalidate()
  container.repaint()
}
