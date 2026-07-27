package packetproxy.common

import java.awt.Color
import javax.swing.text.BadLocationException
import javax.swing.text.Style
import javax.swing.text.StyleConstants
import javax.swing.text.StyledDocument

class JsonSyntaxHighlighter(private val document: StyledDocument) {
  private lateinit var keyStyle: Style
  private lateinit var stringStyle: Style
  private lateinit var numberStyle: Style
  private lateinit var booleanStyle: Style
  private lateinit var nullStyle: Style
  private lateinit var punctuationStyle: Style

  init {
    initializeStyles()
  }

  fun applyHighlightingIfJson() {
    try {
      val text = document.getText(0, document.length)
      val bodyInfo = extractHttpBody(text)
      when {
        bodyInfo != null && isServerSentEvents(bodyInfo.body) ->
          applyServerSentEventsHighlighting(text, bodyInfo)
        bodyInfo != null && isValidJson(bodyInfo.body) ->
          highlightWithJsonParserAtOffset(document, bodyInfo.body, bodyInfo.bodyStartOffset)
        isValidJson(text) -> applyJsonSyntaxHighlighting(text)
        isServerSentEvents(text) -> applyServerSentEventsHighlighting(text, HttpBodyInfo(text, 0))
      }
    } catch (_: BadLocationException) {}
  }

  fun applyJsonSyntaxHighlighting() {
    try {
      applyJsonSyntaxHighlighting(document.getText(0, document.length))
    } catch (_: BadLocationException) {}
  }

  private fun initializeStyles() {
    document.addStyle("default", null)
    keyStyle =
      document.addStyle("key", null).also {
        StyleConstants.setForeground(it, Color(0x92, 0x00, 0x6B))
        StyleConstants.setBold(it, true)
      }
    stringStyle =
      document.addStyle("string", null).also {
        StyleConstants.setForeground(it, Color(0x00, 0x64, 0x00))
      }
    numberStyle =
      document.addStyle("number", null).also {
        StyleConstants.setForeground(it, Color(0x00, 0x00, 0xFF))
      }
    booleanStyle =
      document.addStyle("boolean", null).also {
        StyleConstants.setForeground(it, Color(0x00, 0x00, 0xFF))
      }
    nullStyle =
      document.addStyle("null", null).also {
        StyleConstants.setForeground(it, Color(0x80, 0x80, 0x80))
        StyleConstants.setBold(it, true)
      }
    punctuationStyle =
      document.addStyle("punctuation", null).also {
        StyleConstants.setForeground(it, Color.BLACK)
        StyleConstants.setBold(it, true)
      }
  }

  @Throws(BadLocationException::class)
  private fun applyJsonSyntaxHighlighting(text: String) {
    highlightWithJsonParserAtOffset(document, text, 0)
  }

  private fun isValidJson(text: String): Boolean {
    val trimmed = text.trim()
    return (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
      (trimmed.startsWith("[") && trimmed.endsWith("]"))
  }

  private fun extractHttpBody(text: String): HttpBodyInfo? {
    for (delimiter in arrayOf("\r\n\r\n", "\n\n", "\r\r")) {
      val index = text.indexOf(delimiter)
      val offset = index + delimiter.length
      if (index >= 0 && offset < text.length) return HttpBodyInfo(text.substring(offset), offset)
    }
    return null
  }

  @Throws(BadLocationException::class)
  private fun highlightWithJsonParserAtOffset(doc: StyledDocument, text: String, offset: Int) {
    if (text.isEmpty()) return
    var state = ParseState.NORMAL
    var tokenType = TokenType.UNKNOWN
    var tokenStart = 0
    var expectingKey = false
    var braceDepth = 0
    var unicodeRemaining = 0
    var i = 0
    while (i < text.length) {
      val c = text[i]
      when (state) {
        ParseState.NORMAL ->
          when {
            c.isWhitespace() -> Unit
            c == '{' -> {
              applyStyle(doc, offset + i, 1, punctuationStyle)
              braceDepth++
              expectingKey = true
            }
            c == '}' -> {
              applyStyle(doc, offset + i, 1, punctuationStyle)
              braceDepth--
              expectingKey = false
            }
            c == '[' || c == ']' -> {
              applyStyle(doc, offset + i, 1, punctuationStyle)
              expectingKey = false
            }
            c == ',' -> {
              applyStyle(doc, offset + i, 1, punctuationStyle)
              expectingKey = braceDepth > 0
            }
            c == ':' -> {
              applyStyle(doc, offset + i, 1, punctuationStyle)
              expectingKey = false
              state = ParseState.WAITING_FOR_VALUE
            }
            c == '"' -> {
              tokenStart = i
              tokenType = if (expectingKey) TokenType.KEY else TokenType.STRING_VALUE
              state = ParseState.IN_STRING
            }
            c.isDigit() || c == '-' -> {
              tokenStart = i
              tokenType = TokenType.NUMBER
              state = ParseState.IN_NUMBER
            }
            c == 't' || c == 'f' || c == 'n' -> {
              tokenStart = i
              tokenType = TokenType.BOOLEAN_NULL
              state = ParseState.IN_LITERAL
            }
          }
        ParseState.IN_STRING ->
          when (c) {
            '\\' -> state = ParseState.ESCAPE
            '"' -> {
              applyStyle(
                doc,
                offset + tokenStart,
                i - tokenStart + 1,
                if (tokenType == TokenType.KEY) keyStyle else stringStyle,
              )
              state = ParseState.NORMAL
              expectingKey = false
            }
          }
        ParseState.ESCAPE ->
          state =
            if (c == 'u') {
              unicodeRemaining = 4
              ParseState.ESCAPE_UNICODE
            } else ParseState.IN_STRING
        ParseState.ESCAPE_UNICODE -> {
          if (c.isDigit() || c in 'a'..'f' || c in 'A'..'F') {
            unicodeRemaining--
            if (unicodeRemaining <= 0) state = ParseState.IN_STRING
          } else state = ParseState.IN_STRING
        }
        ParseState.WAITING_FOR_VALUE ->
          if (!c.isWhitespace()) {
            i--
            state = ParseState.NORMAL
          }
        ParseState.IN_NUMBER ->
          if (!c.isDigit() && c !in ".eE+-") {
            applyStyle(doc, offset + tokenStart, i - tokenStart, numberStyle)
            i--
            state = ParseState.NORMAL
          }
        ParseState.IN_LITERAL ->
          if (!c.isLetter()) {
            applyLiteral(doc, text.substring(tokenStart, i), offset + tokenStart, i - tokenStart)
            i--
            state = ParseState.NORMAL
          }
      }
      i++
    }
    if (state == ParseState.IN_NUMBER)
      applyStyle(doc, offset + tokenStart, text.length - tokenStart, numberStyle)
    if (state == ParseState.IN_LITERAL)
      applyLiteral(doc, text.substring(tokenStart), offset + tokenStart, text.length - tokenStart)
  }

  private fun applyLiteral(doc: StyledDocument, literal: String, offset: Int, length: Int) {
    when (literal) {
      "true",
      "false" -> applyStyle(doc, offset, length, booleanStyle)
      "null" -> applyStyle(doc, offset, length, nullStyle)
    }
  }

  private fun applyStyle(doc: StyledDocument, start: Int, length: Int, style: Style) {
    if (start >= 0 && length > 0 && start + length <= doc.length)
      doc.setCharacterAttributes(start, length, style, false)
  }

  private fun isServerSentEvents(text: String): Boolean =
    text.contains("data:") && Regex("(?s).*data:\\s*\\{.*\\}.*").matches(text)

  @Throws(BadLocationException::class)
  private fun applyServerSentEventsHighlighting(fullText: String, bodyInfo: HttpBodyInfo) {
    var currentOffset = bodyInfo.bodyStartOffset
    for (line in bodyInfo.body.split("\n")) {
      val trimmed = line.trim()
      if (trimmed.startsWith("data:")) {
        val value = trimmed.substring(5).trim()
        if (isValidJson(value)) {
          val start = fullText.indexOf(value, currentOffset)
          if (start >= 0) highlightWithJsonParserAtOffset(document, value, start)
        }
      }
      currentOffset += line.length + 1
    }
  }

  private data class HttpBodyInfo(val body: String, val bodyStartOffset: Int)

  private enum class TokenType {
    KEY,
    STRING_VALUE,
    NUMBER,
    BOOLEAN_NULL,
    UNKNOWN,
  }

  private enum class ParseState {
    NORMAL,
    IN_STRING,
    WAITING_FOR_VALUE,
    IN_NUMBER,
    IN_LITERAL,
    ESCAPE,
    ESCAPE_UNICODE,
  }
}
