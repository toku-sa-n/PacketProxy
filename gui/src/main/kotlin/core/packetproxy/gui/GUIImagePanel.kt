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

import java.awt.BorderLayout
import java.io.ByteArrayInputStream
import javax.imageio.ImageIO
import javax.swing.ImageIcon
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.SwingConstants
import packetproxy.common.i18nString

/** 画像レスポンスをプレビューするパネル。HTTPヘッダ付きのデータでもボディを取り出して表示する。 */
class GUIImagePanel {
  private val imageLabel =
    JLabel("", SwingConstants.CENTER).apply { verticalAlignment = SwingConstants.CENTER }
  private val infoLabel = JLabel().apply { foreground = ThemeColors.secondaryForeground() }
  private val panel =
    JPanel(BorderLayout()).apply {
      add(JScrollPane(imageLabel), BorderLayout.CENTER)
      add(infoLabel, BorderLayout.SOUTH)
    }

  fun createPanel(): JComponent = panel

  /** 画像として表示できたときにtrueを返す */
  fun setData(data: ByteArray): Boolean {
    var body = extractImageBytes(data)
    if (body == null) {
      clear()
      return false
    }
    var image =
      try {
        ImageIO.read(ByteArrayInputStream(body))
      } catch (_: Exception) {
        null
      }
    if (image == null) {
      clear()
      return false
    }
    imageLabel.icon = ImageIcon(image)
    imageLabel.text = ""
    infoLabel.text = i18nString("%d x %d, %d bytes", image.width, image.height, body.size)
    return true
  }

  private fun clear() {
    imageLabel.icon = null
    imageLabel.text = i18nString("No image to preview")
    infoLabel.text = ""
  }

  companion object {
    private val HEADER_SEPARATOR = "\r\n\r\n".toByteArray()
    private val IMAGE_MAGICS =
      listOf(
        byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte()),
        byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte()),
        "GIF8".toByteArray(),
        "BM".toByteArray(),
        "RIFF".toByteArray(),
      )

    /** 画像として読めそうなバイト列を返す。画像でなければnullを返す */
    fun extractImageBytes(data: ByteArray): ByteArray? {
      if (data.isEmpty()) {
        return null
      }
      if (startsWithImageMagic(data, 0)) {
        return data
      }
      var bodyOffset = indexOfHeaderSeparator(data)
      if (bodyOffset < 0 || !startsWithImageMagic(data, bodyOffset)) {
        return null
      }
      return data.copyOfRange(bodyOffset, data.size)
    }

    private fun startsWithImageMagic(data: ByteArray, offset: Int): Boolean =
      IMAGE_MAGICS.any { magic -> matchesAt(data, offset, magic) }

    private fun matchesAt(data: ByteArray, offset: Int, pattern: ByteArray): Boolean {
      if (offset + pattern.size > data.size) {
        return false
      }
      for (i in pattern.indices) if (data[offset + i] != pattern[i]) {
        return false
      }
      return true
    }

    /** HTTPヘッダの終端の直後の位置を返す。見つからなければ-1を返す */
    private fun indexOfHeaderSeparator(data: ByteArray): Int {
      // ヘッダは先頭付近にしか現れないので、巨大なボディ全体を走査しない
      var limit = minOf(data.size, MAX_HEADER_SEARCH_SIZE) - HEADER_SEPARATOR.size
      for (i in 0..limit) if (matchesAt(data, i, HEADER_SEPARATOR)) {
        return i + HEADER_SEPARATOR.size
      }
      return -1
    }

    private const val MAX_HEADER_SEARCH_SIZE = 64 * 1024
  }
}
