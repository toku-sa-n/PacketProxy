package packetproxy.extensions.mcp

import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpHandler
import com.sun.net.httpserver.HttpServer
import java.awt.Color
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextPane
import javax.swing.SwingUtilities
import javax.swing.text.BadLocationException
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import javax.swing.text.StyledDocument
import packetproxy.CoreServiceExtension
import packetproxy.CoreServices
import packetproxy.gui.GUIMain
import packetproxy.gui.GuiServiceExtension
import packetproxy.model.Extension
import packetproxy.util.log

enum class LogLevel {
  INFO,
  WARN,
  ERROR,
}

class MCPServerExtension : Extension, CoreServiceExtension, GuiServiceExtension {
  private lateinit var coreServices: CoreServices
  private lateinit var guiMain: GUIMain
  private var server: MCPServer? = null
  private var httpServer: HttpServer? = null
  private var logArea: JTextPane? = null
  private var startButton: JButton? = null
  private var stopButton: JButton? = null
  private var maskTokenCheckBox: JCheckBox? = null
  private var isRunning = false
  private val logMessages: MutableList<LogEntry> = ArrayList()
  private val prettyGson = GsonBuilder().setPrettyPrinting().create()

  private data class LogEntry(val timestamp: Date, val level: LogLevel, val message: String)

  constructor() : super() {
    this.setName("MCP Server")
  }

  @Throws(Exception::class)
  constructor(name: String, path: String) : super(name, path) {
    this.setName("MCP Server")
  }

  @Throws(Exception::class)
  override fun createPanel(): JComponent {
    var panel = JPanel()
    panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

    // Status panel
    var statusPanel = JPanel()
    statusPanel.setLayout(BoxLayout(statusPanel, BoxLayout.X_AXIS))
    statusPanel.add(JLabel("MCP Server Status: "))

    startButton = JButton("Start Server")
    stopButton = JButton("Stop Server")
    stopButton!!.setEnabled(false)

    maskTokenCheckBox = JCheckBox("Mask access_token in logs", true)
    maskTokenCheckBox!!.setToolTipText(
      "When enabled, access_token values are masked with asterisks in log display"
    )
    maskTokenCheckBox!!.setBorder(BorderFactory.createEmptyBorder(0, 15, 0, 0))
    maskTokenCheckBox!!.addActionListener(
      object : ActionListener {
        override fun actionPerformed(e: ActionEvent) {
          refreshLogDisplay()
        }
      }
    )

    startButton!!.addActionListener(
      object : ActionListener {
        override fun actionPerformed(e: ActionEvent) {
          startServer()
        }
      }
    )

    stopButton!!.addActionListener(
      object : ActionListener {
        override fun actionPerformed(e: ActionEvent) {
          stopServer()
        }
      }
    )

    statusPanel.add(startButton)
    statusPanel.add(stopButton)
    statusPanel.add(maskTokenCheckBox)

    // Log area
    logArea = JTextPane()
    logArea!!.setEditable(false)
    var scrollPane = JScrollPane(logArea)
    scrollPane.verticalScrollBar.unitIncrement = 16

    panel.add(statusPanel)
    panel.add(JLabel("Server Logs:"))
    panel.add(scrollPane)

    return panel
  }

  override fun historyClickHandler(): JMenuItem? {
    return null // MCP Serverは右クリックメニューに追加しない
  }

  override fun initialize(coreServices: CoreServices) {
    this.coreServices = coreServices
  }

  override fun initialize(guiMain: GUIMain) {
    this.guiMain = guiMain
  }

  private fun startServer() {
    if (isRunning) {
      return
    }

    try {
      server =
        MCPServer(coreServices, guiMain.getGuiResender()) { level, message ->
          addLog(message, level)
        }

      // Start HTTP server for MCP
      httpServer = HttpServer.create(InetSocketAddress(HTTP_PORT), 0)
      httpServer!!.createContext("/mcp", MCPHttpHandler())
      httpServer!!.setExecutor(null) // creates a default executor
      httpServer!!.start()

      var serverThread = Thread {
        try {
          server!!.run()
        } catch (e: Exception) {
          addLog("Server error: " + e.message, LogLevel.ERROR)
          e.printStackTrace()
        }
      }
      serverThread.setDaemon(true)
      serverThread.start()

      isRunning = true
      startButton!!.setEnabled(false)
      stopButton!!.setEnabled(true)
      addLog("MCP Server started")
      addLog("HTTP endpoint available at http://localhost:$HTTP_PORT/mcp")
      log("MCP Server started with HTTP endpoint on port $HTTP_PORT")
    } catch (e: Exception) {
      addLog("Failed to start server: " + e.message, LogLevel.ERROR)
      e.printStackTrace()
    }
  }

  private fun stopServer() {
    if (!isRunning) {
      return
    }

    try {
      if (server != null) {
        server!!.stop()
        server = null
      }

      if (httpServer != null) {
        httpServer!!.stop(0)
        httpServer = null
      }

      isRunning = false
      startButton!!.setEnabled(true)
      stopButton!!.setEnabled(false)
      addLog("MCP Server stopped")
      log("MCP Server stopped")
    } catch (e: Exception) {
      addLog("Failed to stop server: " + e.message, LogLevel.ERROR)
      e.printStackTrace()
    }
  }

  private fun addLog(message: String, level: LogLevel = LogLevel.INFO) {
    var entry = LogEntry(Date(), level, message)
    synchronized(logMessages) { logMessages.add(entry) }
    if (logArea != null) {
      SwingUtilities.invokeLater { appendStyledEntry(entry) }
    }
  }

  private fun appendStyledEntry(entry: LogEntry) {
    var area = logArea ?: return
    try {
      var doc: StyledDocument = area.styledDocument
      var displayMessage =
        if (maskTokenCheckBox!!.isSelected) maskAccessToken(entry.message) else entry.message
      var prefix = "[${entry.timestamp}] [${entry.level}] "
      var body = displayMessage + "\n"

      var prefixAttrs = SimpleAttributeSet()
      StyleConstants.setForeground(prefixAttrs, PREFIX_COLOR)
      StyleConstants.setBold(prefixAttrs, true)

      var bodyAttrs = styleForLevel(entry.level)

      doc.insertString(doc.length, prefix, prefixAttrs)
      doc.insertString(doc.length, body, bodyAttrs)
      area.setCaretPosition(doc.length)
    } catch (_: BadLocationException) {}
  }

  private fun styleForLevel(level: LogLevel): SimpleAttributeSet {
    var attrs = SimpleAttributeSet()
    when (level) {
      LogLevel.ERROR -> {
        StyleConstants.setBackground(attrs, ERROR_BG)
        StyleConstants.setBold(attrs, true)
      }
      LogLevel.WARN -> {
        StyleConstants.setForeground(attrs, WARN_FG)
      }
      LogLevel.INFO -> {
        // default foreground
      }
    }
    return attrs
  }

  private fun refreshLogDisplay() {
    if (logArea != null) {
      SwingUtilities.invokeLater {
        try {
          var doc: StyledDocument = logArea!!.styledDocument
          doc.remove(0, doc.length)
          synchronized(logMessages) {
            for (entry in logMessages) {
              appendStyledEntry(entry)
            }
          }
        } catch (_: BadLocationException) {}
      }
    }
  }

  private fun prettyPrintJson(raw: String): String {
    return try {
      prettyGson.toJson(JsonParser.parseString(raw))
    } catch (_: Exception) {
      raw
    }
  }

  private fun maskAccessToken(message: String): String {
    // Pattern to match "access_token":"value" or "access_token": "value" or
    // access_token=value
    return message.replace(
      "(?i)(\"?access_token\"?\\s*[:=]\\s*\"?)([^\"\\s&,}]+)(\"?)".toRegex(),
      "$1****$3",
    )
  }

  // HTTP handler for MCP requests
  private inner class MCPHttpHandler : HttpHandler {
    @Throws(IOException::class)
    override fun handle(exchange: HttpExchange) {
      addLog(
        "Received HTTP request: " + exchange.getRequestMethod() + " " + exchange.getRequestURI()
      )

      // Enable CORS
      exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*")
      exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS")
      exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type")

      if ("OPTIONS" == exchange.getRequestMethod()) {
        exchange.sendResponseHeaders(200, 0)
        exchange.getResponseBody().close()
        return
      }

      if ("POST" != exchange.getRequestMethod()) {
        var response = "Only POST method is supported"
        exchange.sendResponseHeaders(405, response.length.toLong())
        var os = exchange.getResponseBody()
        os.write(response.toByteArray())
        os.close()
        return
      }

      try {
        // Read request body
        var requestBodyStream = exchange.getRequestBody()
        var requestBody = String(requestBodyStream.readBytes(), StandardCharsets.UTF_8)
        addLog("Request body:\n" + prettyPrintJson(requestBody))

        // Process MCP request if server is available
        var responseBody: String
        if (server != null) {
          try {
            var request = JsonParser.parseString(requestBody).getAsJsonObject()
            var result = server!!.processTestRequest(request)
            responseBody = result.toString()
            addLog("Response:\n" + prettyPrintJson(responseBody))
          } catch (e: Exception) {
            addLog("Error processing request: " + e.message, LogLevel.ERROR)
            responseBody =
              "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error: " +
                e.message +
                "\"},\"id\":null}"
          }
        } else {
          responseBody =
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32002,\"message\":\"Server not available\"},\"id\":null}"
        }

        // Send response
        exchange.getResponseHeaders().add("Content-Type", "application/json")
        exchange.sendResponseHeaders(
          200,
          responseBody.toByteArray(StandardCharsets.UTF_8).size.toLong(),
        )
        var os = exchange.getResponseBody()
        os.write(responseBody.toByteArray(StandardCharsets.UTF_8))
        os.close()
      } catch (e: Exception) {
        addLog("HTTP handler error: " + e.message, LogLevel.ERROR)
        var errorResponse =
          "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}"
        exchange.sendResponseHeaders(500, errorResponse.length.toLong())
        var os = exchange.getResponseBody()
        os.write(errorResponse.toByteArray())
        os.close()
      }
    }
  }

  companion object {
    private val HTTP_PORT = 8765
    private val ERROR_BG = Color(240, 150, 150)
    private val WARN_FG = Color(180, 100, 0)
    private val PREFIX_COLOR = Color(100, 100, 100)
  }
}
