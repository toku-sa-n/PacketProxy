package packetproxy.extensions.mcp

import com.google.gson.JsonParser
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpHandler
import com.sun.net.httpserver.HttpServer
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
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import packetproxy.model.Extension
import packetproxy.util.Logging.log

class MCPServerExtension : Extension {
  private var server: MCPServer? = null
  private var httpServer: HttpServer? = null
  private var logArea: JTextArea? = null
  private var startButton: JButton? = null
  private var stopButton: JButton? = null
  private var maskTokenCheckBox: JCheckBox? = null
  private var isRunning = false
  private val logMessages: MutableList<String> = ArrayList()

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
    logArea = JTextArea(20, 80)
    logArea!!.setEditable(false)
    var scrollPane = JScrollPane(logArea)

    panel.add(statusPanel)
    panel.add(JLabel("Server Logs:"))
    panel.add(scrollPane)

    return panel
  }

  override fun historyClickHandler(): JMenuItem? {
    return null // MCP Serverは右クリックメニューに追加しない
  }

  private fun startServer() {
    if (isRunning) {
      return
    }

    try {
      server = MCPServer { message -> addLog(message) }

      // Start HTTP server for MCP
      httpServer = HttpServer.create(InetSocketAddress(HTTP_PORT), 0)
      httpServer!!.createContext("/mcp", MCPHttpHandler())
      httpServer!!.setExecutor(null) // creates a default executor
      httpServer!!.start()

      var serverThread = Thread {
        try {
          server!!.run()
        } catch (e: Exception) {
          addLog("Server error: " + e.message)
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
      addLog("Failed to start server: " + e.message)
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
      addLog("Failed to stop server: " + e.message)
      e.printStackTrace()
    }
  }

  private fun addLog(message: String) {
    synchronized(logMessages) { logMessages.add(message) }
    if (logArea != null) {
      SwingUtilities.invokeLater {
        var displayMessage =
          if (maskTokenCheckBox!!.isSelected) maskAccessToken(message) else message
        logArea!!.append("[" + Date() + "] " + displayMessage + "\n")
        logArea!!.setCaretPosition(logArea!!.getDocument().getLength())
      }
    }
  }

  private fun refreshLogDisplay() {
    if (logArea != null) {
      SwingUtilities.invokeLater {
        logArea!!.setText("")
        synchronized(logMessages) {
          for (message in logMessages) {
            var displayMessage =
              if (maskTokenCheckBox!!.isSelected) maskAccessToken(message) else message
            logArea!!.append("[" + Date() + "] " + displayMessage + "\n")
          }
        }
        logArea!!.setCaretPosition(logArea!!.getDocument().getLength())
      }
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
        addLog("Request body: $requestBody")

        // Process MCP request if server is available
        var responseBody: String
        if (server != null) {
          try {
            var request = JsonParser.parseString(requestBody).getAsJsonObject()
            var result = server!!.processTestRequest(request)
            responseBody = result.toString()
            addLog("Response: $responseBody")
          } catch (e: Exception) {
            addLog("Error processing request: " + e.message)
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
        addLog("HTTP handler error: " + e.message)
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
    private const val HTTP_PORT = 8765
  }
}
