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
import java.awt.Component
import java.nio.charset.StandardCharsets
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JTable
import javax.swing.table.TableCellRenderer
import javax.swing.table.TableRowSorter
import packetproxy.common.i18nString
import packetproxy.common.i18nStringArray
import packetproxy.http.HeaderField
import packetproxy.http.HttpHeader
import packetproxy.http.QueryParameter
import packetproxy.model.OptionTableModel

/** [TabSet]の固定タブの後ろに追加されるHTTP構造化タブの種別。表示順はこの宣言順。 */
internal enum class HttpStructuredTabKind(val title: String) {
  HEADERS("Headers"),
  QUERY("Query"),
  COOKIES("Cookies"),
}

/**
 * HTTPパケットのヘッダ・クエリ文字列・Cookieを読み取り専用のテーブルで見せる。
 *
 * 編集はRawタブに任せる方針なのでテーブルはすべて非編集。解析はヘッダ部だけを[HttpHeader]に渡して行うため、
 * gzipやzstdで圧縮されたボディを持つパケットでも展開コストが発生しない。
 */
internal class HttpStructuredTabs(private val owner: GUIMain) {
  private companion object {
    private const val NAME_COLUMN_WIDTH = 200
    private const val VALUE_COLUMN_WIDTH = 400
    private const val REQUEST_COOKIE_HEADER = "Cookie"
    private const val RESPONSE_COOKIE_HEADER = "Set-Cookie"
    private val REQUEST_LINE_PATTERN = Regex("""^\S+ +(\S+) +HTTP/[0-9.]+$""")
    private val RESPONSE_LINE_PATTERN = Regex("""^HTTP/[0-9.]+(\s.*)?$""")
  }

  /* 非HTTPのパケットではテーブルを作らずに済むよう、実体は初回表示まで遅延させる */
  private val headersTable by lazy {
    KeyValueTable(i18nStringArray("Name", "Value"), i18nString("This packet has no header field."))
  }
  private val queryTable by lazy {
    KeyValueTable(
      i18nStringArray("Name", "Value"),
      i18nString("This request has no query parameter."),
    )
  }
  private val cookiesTable by lazy {
    KeyValueTable(
      i18nStringArray("Name", "Value", "Attributes"),
      i18nString("This packet has no cookie."),
    )
  }

  fun panelOf(kind: HttpStructuredTabKind): JComponent = tableOf(kind).panel

  /** [data]を解析してテーブルを更新し、表示すべきタブ種別を並び順で返す。HTTPに見えないときは空。 */
  fun setData(data: ByteArray): List<HttpStructuredTabKind> {
    var structure = parse(data) ?: return emptyList()
    var kinds = mutableListOf(HttpStructuredTabKind.HEADERS)
    if (structure.queryRows.isNotEmpty()) {
      kinds.add(HttpStructuredTabKind.QUERY)
    }
    if (structure.cookieRows.isNotEmpty()) {
      kinds.add(HttpStructuredTabKind.COOKIES)
    }
    kinds.forEach { tableOf(it).setRows(structure.rowsOf(it)) }
    return kinds
  }

  private fun tableOf(kind: HttpStructuredTabKind): KeyValueTable =
    when (kind) {
      HttpStructuredTabKind.HEADERS -> headersTable
      HttpStructuredTabKind.QUERY -> queryTable
      HttpStructuredTabKind.COOKIES -> cookiesTable
    }

  private fun parse(data: ByteArray): HttpStructure? {
    var headerSize = HttpHeader.calcHeaderSize(data)
    if (headerSize <= 0) {
      return null
    }
    var statusLine = parseStatusLine(firstLine(data, headerSize)) ?: return null
    /* ボディを渡すと改行コードの推測がボディ側の文字に引きずられるので、ヘッダ部だけを解析させる */
    var fields = HttpHeader(data.copyOfRange(0, headerSize)).getFields()
    return HttpStructure(
      headerRows = fields.map { arrayOf<Any?>(it.getName(), it.getValue()) },
      queryRows = if (statusLine.isRequest) queryRows(statusLine.query) else emptyList(),
      cookieRows = cookieRows(fields),
    )
  }

  /** リクエストラインかステータスラインなら解析結果を返す。どちらでもなければHTTPではないと見なす。 */
  private fun parseStatusLine(line: String): StatusLine? {
    if (RESPONSE_LINE_PATTERN.matches(line)) {
      return StatusLine(isRequest = false, query = "")
    }
    var request = REQUEST_LINE_PATTERN.matchEntire(line) ?: return null
    var target = request.groupValues[1]
    var separator = target.indexOf('?')
    if (separator < 0) {
      return StatusLine(isRequest = true, query = "")
    }
    return StatusLine(isRequest = true, query = target.substring(separator + 1))
  }

  /** ヘッダ部の1行目を取り出す。[HttpHeader]と同じく先頭の改行は読み飛ばす。 */
  private fun firstLine(data: ByteArray, headerSize: Int): String {
    var start = 0
    while (start < headerSize && isNewLine(data[start])) {
      start++
    }
    var end = start
    while (end < headerSize && data[end] != '\n'.code.toByte()) {
      end++
    }
    if (end > start && data[end - 1] == '\r'.code.toByte()) {
      end--
    }
    return String(data, start, end - start, StandardCharsets.ISO_8859_1)
  }

  private fun isNewLine(byte: Byte): Boolean =
    byte == '\r'.code.toByte() || byte == '\n'.code.toByte()

  private fun queryRows(query: String): List<Array<Any?>> =
    query
      .split("&")
      .map { QueryParameter(it) }
      .filter { !it.getName().isNullOrEmpty() }
      .map { arrayOf<Any?>(it.getName(), it.getValue() ?: "") }

  private fun cookieRows(fields: List<HeaderField>): List<Array<Any?>> {
    var rows = mutableListOf<Array<Any?>>()
    for (field in fields) {
      if (field.getName().equals(REQUEST_COOKIE_HEADER, ignoreCase = true)) {
        rows.addAll(requestCookieRows(field.getValue()))
        continue
      }
      if (field.getName().equals(RESPONSE_COOKIE_HEADER, ignoreCase = true)) {
        rows.add(responseCookieRow(field.getValue()) ?: continue)
      }
    }
    return rows
  }

  /** `Cookie: a=1; b=2`を1行ずつに分解する。リクエストのCookieに属性は無い。 */
  private fun requestCookieRows(value: String): List<Array<Any?>> =
    value.split(";").mapNotNull { pair ->
      var cookie = pair.trim()
      if (cookie.isEmpty()) {
        return@mapNotNull null
      }
      var separator = cookie.indexOf('=')
      if (separator < 0) {
        return@mapNotNull arrayOf<Any?>(cookie, "", "")
      }
      arrayOf<Any?>(cookie.substring(0, separator), cookie.substring(separator + 1), "")
    }

  /** `Set-Cookie: sid=xxx; Path=/; HttpOnly`を1行にまとめ、2つ目以降のセミコロン区切りを属性列に入れる。 */
  private fun responseCookieRow(value: String): Array<Any?>? {
    var parts = value.split(";")
    var cookie = parts.first().trim()
    if (cookie.isEmpty()) {
      return null
    }
    var attributes = parts.drop(1).map { it.trim() }.filter { it.isNotEmpty() }.joinToString("; ")
    var separator = cookie.indexOf('=')
    if (separator < 0) {
      return arrayOf(cookie, "", attributes)
    }
    return arrayOf(cookie.substring(0, separator), cookie.substring(separator + 1), attributes)
  }

  private class StatusLine(val isRequest: Boolean, val query: String)

  private class HttpStructure(
    val headerRows: List<Array<Any?>>,
    val queryRows: List<Array<Any?>>,
    val cookieRows: List<Array<Any?>>,
  ) {
    fun rowsOf(kind: HttpStructuredTabKind): List<Array<Any?>> =
      when (kind) {
        HttpStructuredTabKind.HEADERS -> headerRows
        HttpStructuredTabKind.QUERY -> queryRows
        HttpStructuredTabKind.COOKIES -> cookieRows
      }
  }

  /** 名前と値を並べるだけの読み取り専用テーブル。セル選択は残してコピーできるようにしている。 */
  private inner class KeyValueTable(columnNames: Array<String>, emptyMessage: String) {
    val panel = JPanel(BorderLayout())

    private val model =
      object : OptionTableModel(columnNames, 0) {
        override fun isCellEditable(row: Int, column: Int): Boolean = false
      }

    private val table =
      object : JTable(model) {
        override fun prepareRenderer(
          renderer: TableCellRenderer,
          row: Int,
          column: Int,
        ): Component {
          var component = super.prepareRenderer(renderer, row, column)
          if (isRowSelected(row)) {
            component.foreground = ThemeColors.tableSelectionForeground()
            component.background = ThemeColors.tableSelectionBackground()
            return component
          }
          component.foreground = ThemeColors.textForeground()
          component.background =
            if (row % 2 == 0) ThemeColors.tableBackground() else ThemeColors.tableAlternateRow()
          return component
        }
      }

    private val emptyLabel = emptyStateLabel(emptyMessage)

    init {
      table.rowSorter = TableRowSorter(model)
      table.rowHeight = owner.modelServices.fontManager.getUIFontHeight(table)
      table.autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
      table.cellSelectionEnabled = true
      table.background = ThemeColors.tableBackground()
      table.gridColor = ThemeColors.separatorColor()
      table.columnModel.getColumn(0).preferredWidth = NAME_COLUMN_WIDTH
      if (table.columnModel.columnCount > 2) {
        table.columnModel.getColumn(1).preferredWidth = VALUE_COLUMN_WIDTH
      }
      panel.add(emptyLabel, BorderLayout.NORTH)
      panel.add(CustomScrollPane().apply { viewport.view = table }, BorderLayout.CENTER)
    }

    fun setRows(rows: List<Array<Any?>>) {
      model.rowCount = 0
      rows.forEach { model.addRow(it) }
      emptyLabel.setEmptyStateVisible(rows.isEmpty(), panel)
    }
  }
}
