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

import java.text.ParseException
import java.util.HashSet
import java.util.TreeSet
import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException
import javax.swing.RowFilter
import javax.swing.RowFilter.ComparisonType
import javax.swing.table.DefaultTableModel
import org.apache.commons.collections4.map.HashedMap
import packetproxy.model.Packet
import packetproxy.model.Packets
import packetproxy.util.errWithStackTrace

/**
 * Filterのパーサー 文法は以下の通り <Expr> ::= <OrExpr> <OrExpr> ::= <AndExpr> | <AndExpr> '||' <OrExpr>
 * <AndEexpr> ::= <PrimaryExpr> | <PrimaryExpr> '&&' <AndExpr> <PrimaryExpr> ::= <Lhs> <Operator>
 * <Rhs> | '(' <Expr> ')' <Lhs> ::= HashedMapのkeys <Rhs> ::= [^&|()]+ <Operator> ::= '=~' | '==' |
 * '>=' | '<=' | '!~' | '!='
 */
class FilterTextParser
private constructor(
  private val str: String,
  private val table: DefaultTableModel,
  private val packets: Packets,
) {
  private var index = 0

  @Throws(Exception::class) private fun expr(): RowFilter<Any, Any> = orExpr()

  @Throws(Exception::class)
  private fun orExpr(): RowFilter<Any, Any> {
    val filters = ArrayList<RowFilter<Any, Any>>()
    filters.add(andExpr())
    while (getNextChar() == '|') {
      index++
      if (getNextChar() != '|') {
        throw ParseException("| token is missing", index)
      }
      index++
      filters.add(andExpr())
    }
    if (filters.size == 1) {
      return filters[0]
    }
    return RowFilter.orFilter(filters)
  }

  @Throws(Exception::class)
  private fun andExpr(): RowFilter<Any, Any> {
    val filters = ArrayList<RowFilter<Any, Any>>()
    filters.add(primaryExpr())
    while (getNextChar() == '&') {
      index++
      if (getNextChar() != '&') {
        throw ParseException("& token is missing", index)
      }
      index++
      filters.add(primaryExpr())
    }
    if (filters.size == 1) {
      return filters[0]
    }
    return RowFilter.andFilter(filters)
  }

  @Throws(Exception::class)
  private fun primaryExpr(): RowFilter<Any, Any> {
    if (getNextChar() == '(') {
      index++
      val ret = expr()
      if (getNextChar() != ')') {
        throw ParseException(") token is missing", index)
      }
      index++
      return ret
    }

    var lhs = ""
    while (true) {
      val c = getNextChar()
      if (!Character.isAlphabetic(c.code) && c != '_') {
        break
      }
      lhs += c
      index++
    }
    if (!columnMapper.containsKey(lhs)) {
      throw ParseException("column name in invalid: $lhs", index)
    }
    val column = columnMapper[lhs]!!

    var operator = "" + getNextChar()
    index++
    if (index >= str.length) {
      throw ParseException("unexpected end", index)
    }
    var c = str[index]
    if (c == '=' || c == '~') {
      operator += c
      index++
    }

    var rhs = ""
    if (index >= str.length) {
      throw ParseException("unexpected end", index)
    }
    while (index < str.length) {
      c = str[index]
      if (c == '(' || c == ')' || c == '|' || c == '&') {
        break
      }
      rhs += c
      index++
    }
    rhs = rhs.trim()

    val filter: RowFilter<Any, Any> =
      if (operator == "!~" || operator == "!=") {
        RowFilter.notFilter(generateRequestRowFilter(rhs, column, table))
      } else if (operator == "=~" || operator == "==") {
        when (column) {
          columnMapper["full_text_i"] -> generateFullTextRowFilter_i(rhs, packets)
          columnMapper["full_text"] -> generateFullTextRowFilter(rhs, packets)
          else -> generateRequestRowFilter(rhs, column, table)
        }
      } else if (operator == "<=") {
        RowFilter.numberFilter(ComparisonType.BEFORE, Integer.parseInt(rhs), column)
      } else if (operator == ">=") {
        RowFilter.numberFilter(ComparisonType.AFTER, Integer.parseInt(rhs), column)
      } else {
        throw ParseException("operator is invalid: $operator", index)
      }
    return filter
  }

  @Throws(Exception::class)
  private fun getNextChar(): Char {
    var c = '\u0000'
    while (index < str.length) {
      c = str[index]
      if (!Character.isWhitespace(c)) {
        break
      }
      index++
    }
    return c
  }

  private open class RequestRowFilter(
    searchWord: String,
    columns: IntArray,
    private val table: DefaultTableModel,
  ) : MyGeneralFilter(columns) {
    val groupIds: MutableSet<Long> = HashSet()
    private val searchWord: String = searchWord
    private var already_analyzed_row_num = 0

    override fun include(value: RowFilter.Entry<out Any, out Any>, index: Int): Boolean {
      if (!validPattern(searchWord)) {
        return false
      }
      val v = value.getValue(columnMapper["group"]!!)
      if (v is Long) {
        try {
          if (already_analyzed_row_num < table.rowCount) {
            for (i in already_analyzed_row_num until table.rowCount) {
              val data = table.getValueAt(i, index) as String?
              if (data != null && data.matches(Regex(".*$searchWord.*"))) {
                groupIds.add(table.getValueAt(i, columnMapper["group"]!!) as Long)
              }
            }
            already_analyzed_row_num = table.rowCount
          } else {
            val data = value.getValue(index) as String?
            if (data != null && data.matches(Regex(".*$searchWord.*"))) {
              groupIds.add(value.getValue(columnMapper["group"]!!) as Long)
            }
          }
        } catch (e: Exception) {
          errWithStackTrace(e)
        }
        return groupIds.stream().anyMatch { g -> g == v }
      }
      return false
    }
  }

  private open class FullTextRowFilter(searchWord: String, columns: IntArray) :
    MyGeneralFilter(columns) {
    val groupIds: MutableSet<Long> = TreeSet()
    private val searchWord: String = searchWord

    override fun include(value: RowFilter.Entry<out Any, out Any>, index: Int): Boolean {
      if (!validPattern(searchWord)) {
        return false
      }
      val v = value.getValue(index)
      if (v is Long) {
        return groupIds.contains(v)
      }
      return false
    }
  }

  private abstract class MyGeneralFilter(private val columns: IntArray) : RowFilter<Any, Any>() {
    override fun include(value: Entry<out Any, out Any>): Boolean {
      var count = value.valueCount
      if (columns.isNotEmpty()) {
        for (i in columns.indices.reversed()) {
          val index = columns[i]
          if (index < count) {
            if (include(value, index)) {
              return true
            }
          }
        }
      } else {
        while (--count >= 0) {
          if (include(value, count)) {
            return true
          }
        }
      }
      return false
    }

    protected abstract fun include(value: Entry<out Any, out Any>, index: Int): Boolean
  }

  companion object {
    private val columnMapper =
      HashedMap<String, Int>().apply {
        put("id", 0)
        put("request", 1)
        put("response", 2)
        put("length", 3)
        put("client_ip", 4)
        put("client_port", 5)
        put("server_ip", 6)
        put("server_port", 7)
        put("time", 8)
        put("resend", 9)
        put("modified", 10)
        put("type", 11)
        put("encode", 12)
        put("alpn", 13)
        put("group", 14)
        put("full_text", 15)
        put("full_text_i", 16)
      }

    @JvmStatic
    @Throws(ParseException::class, Exception::class)
    fun parse(str: String, table: DefaultTableModel, packets: Packets): RowFilter<Any, Any> =
      FilterTextParser(str, table, packets).expr()

    @Throws(Exception::class)
    private fun generateRequestRowFilter(
      searchWord: String,
      column: Int,
      table: DefaultTableModel,
    ): RowFilter<Any, Any> = RequestRowFilter(searchWord, intArrayOf(column), table)

    // case sensitive full text search
    @Throws(Exception::class)
    private fun generateFullTextRowFilter(
      searchWord: String,
      packets: Packets,
    ): RowFilter<Any, Any> {
      val fullTextRowFilter = FullTextRowFilter(searchWord, intArrayOf(columnMapper["group"]!!))
      val result: List<Packet> = packets.queryFullText(searchWord)
      result.forEach { p -> fullTextRowFilter.groupIds.add(p.getGroup()) }
      return fullTextRowFilter
    }

    // case insensitive full text search
    @Throws(Exception::class)
    private fun generateFullTextRowFilter_i(
      searchWord: String,
      packets: Packets,
    ): RowFilter<Any, Any> {
      val fullTextRowFilter = FullTextRowFilter(searchWord, intArrayOf(columnMapper["group"]!!))
      val result: List<Packet> = packets.queryFullText_i(searchWord)
      result.forEach { p -> fullTextRowFilter.groupIds.add(p.getGroup()) }
      return fullTextRowFilter
    }

    private fun validPattern(searchWord: String): Boolean {
      try {
        Pattern.compile(searchWord)
      } catch (_: PatternSyntaxException) {
        return false
      }
      return true
    }
  }
}
