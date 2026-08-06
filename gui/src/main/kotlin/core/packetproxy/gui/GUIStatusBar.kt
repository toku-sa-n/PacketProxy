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

import java.awt.Dimension
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JLabel
import javax.swing.JPanel
import packetproxy.common.i18nString

/** ウィンドウ下端の状態バー。History の件数、Intercept の状態、待ち受けポートを表示する。 */
class GUIStatusBar : JPanel() {

  private val historyLabel = createLabel()
  private val interceptLabel = createLabel()
  private val listenPortLabel = createLabel()
  private val separators = mutableListOf<JLabel>()
  private var interceptEnabled = false
  private var interceptWaiting = false

  init {
    layout = BoxLayout(this, BoxLayout.X_AXIS)
    border = BorderFactory.createEmptyBorder(2, 8, 3, 8)
    isOpaque = true
    add(historyLabel)
    add(createSeparator())
    add(interceptLabel)
    add(createSeparator())
    add(listenPortLabel)
    add(Box.createHorizontalGlue())
    updateHistoryCount(0, 0)
    updateInterceptState(false)
    updateListenPorts(emptyList())
    refreshTheme()
    maximumSize = Dimension(Short.MAX_VALUE.toInt(), preferredSize.height)
  }

  /** フィルタ後の表示件数と全件数を表示する。 */
  fun updateHistoryCount(displayed: Int, total: Int) {
    onEDT { historyLabel.text = i18nString("History %d / %d", displayed, total) }
  }

  fun updateInterceptState(enabled: Boolean) {
    onEDT {
      interceptEnabled = enabled
      refreshInterceptLabel()
    }
  }

  /** インターセプトしたパケットがユーザー操作を待っているかどうかを表示する。 */
  fun updateInterceptWaiting(waiting: Boolean) {
    onEDT {
      interceptWaiting = waiting
      refreshInterceptLabel()
    }
  }

  private fun refreshInterceptLabel() {
    if (!interceptEnabled) {
      interceptLabel.text = i18nString("Intercept OFF")
      interceptLabel.foreground = ThemeColors.secondaryForeground()
      return
    }
    interceptLabel.text =
      if (interceptWaiting) i18nString("Intercept ON (1 waiting)") else i18nString("Intercept ON")
    interceptLabel.foreground = ThemeColors.emphasisForeground()
  }

  fun updateListenPorts(ports: List<Int>) {
    onEDT {
      if (ports.isEmpty()) {
        listenPortLabel.text = i18nString("No listening port")
        return@onEDT
      }
      listenPortLabel.text = i18nString("Listening %s", summarize(ports))
    }
  }

  /** テーマ切り替え後に、明示指定した色を現在のテーマの色へ差し替える。 */
  fun refreshTheme() {
    background = ThemeColors.panelBackground()
    for (label in listOf(historyLabel, listenPortLabel) + separators) {
      label.foreground = ThemeColors.secondaryForeground()
    }
    updateInterceptState(interceptEnabled)
  }

  private fun summarize(ports: List<Int>): String {
    if (ports.size <= MAX_SHOWN_PORTS) {
      return ports.joinToString(", ")
    }
    var shown = ports.take(MAX_SHOWN_PORTS).joinToString(", ")
    return "$shown +${ports.size - MAX_SHOWN_PORTS}"
  }

  private fun createSeparator(): JLabel {
    var separator = createLabel()
    separator.text = SEPARATOR_TEXT
    separators.add(separator)
    return separator
  }

  private fun createLabel(): JLabel {
    var label = JLabel()
    label.foreground = ThemeColors.secondaryForeground()
    return label
  }

  companion object {
    private const val MAX_SHOWN_PORTS = 4
    private const val SEPARATOR_TEXT = "   |   "
  }
}
