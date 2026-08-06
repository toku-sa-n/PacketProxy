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

import com.formdev.flatlaf.extras.FlatSVGIcon
import java.awt.Color
import javax.swing.Icon

/**
 * ツールバーやタブで使うアイコンを提供する。
 *
 * SVGを単色で塗り直して返すため、テーマを切り替えても文字色と揃った見た目になる。塗り色は描画のたびに評価されるので、 生成済みのアイコンを保持していてもテーマ変更に追従する。
 */
object GuiIcons {

  fun plus(): Icon = tinted("plus", 12) { ThemeColors.textForeground() }

  fun close(): Icon = tinted("close", 11) { ThemeColors.secondaryForeground() }

  /** タブの閉じるボタンにマウスが乗っているときのアイコン。 */
  fun closeHovered(): Icon = tinted("close", 11) { ThemeColors.errorForeground() }

  fun config(): Icon = tinted("config", 13) { ThemeColors.textForeground() }

  fun arrow(): Icon = tinted("arrow", 10) { ThemeColors.textForeground() }

  fun autoScrollEnabled(): Icon =
    tinted("auto_scroll_enabled", 14) { ThemeColors.emphasisForeground() }

  fun autoScrollDisabled(): Icon =
    tinted("auto_scroll_disabled", 14) { ThemeColors.secondaryForeground() }

  private fun tinted(name: String, size: Int, color: () -> Color): Icon {
    var icon = FlatSVGIcon("gui/$name.svg", size, size)
    icon.colorFilter = FlatSVGIcon.ColorFilter { color() }
    return icon
  }
}
