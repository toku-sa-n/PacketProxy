package packetproxy.common

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import fi.iki.elonen.NanoHTTPD
import javax.swing.JOptionPane
import packetproxy.gui.GUIMain
import packetproxy.model.Database
import packetproxy.model.ListenPorts
import packetproxy.model.Modifications
import packetproxy.model.SSLPassThroughs
import packetproxy.model.Servers

class ConfigHttpServer(hostname: String, port: Int, private val allowedAccessToken: String) :
  NanoHTTPD(hostname, port) {
  override fun serve(session: IHTTPSession): Response {
    if (session.method == Method.OPTIONS && session.uri == "/config") {
      return newFixedLengthResponse(Response.Status.OK, MIME_HTML, null).apply {
        addHeader("Access-Control-Allow-Origin", "*")
        addHeader("Access-Control-Allow-Headers", "Authorization,Content-Type")
        addHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        addHeader("Access-Control-Allow-Private-Network", "true")
        addHeader("Access-Control-Max-Age", "86400")
      }
    }
    if (allowedAccessToken != session.headers["authorization"]) {
      return newFixedLengthResponse(Response.Status.UNAUTHORIZED, MIME_HTML, null)
    }
    return when {
      session.method == Method.GET && session.uri == "/config" -> getConfig()
      session.method == Method.POST && session.uri == "/config" -> postConfig(session)
      else -> newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_HTML, null)
    }
  }

  private fun getConfig(): Response =
    try {
      val daoHub =
        ConfigDaoHub().apply {
          listenPortList = ListenPorts.getInstance().queryAll()
          serverList = Servers.getInstance().queryAll()
          modificationList = Modifications.getInstance().queryAll()
          sslPassThroughList = SSLPassThroughs.getInstance().queryAll()
        }
      fixUp(daoHub)
      newFixedLengthResponse(
          Response.Status.OK,
          MIME_HTML,
          GsonBuilder().setPrettyPrinting().create().toJson(daoHub),
        )
        .apply { addHeader("Access-Control-Allow-Origin", "*") }
    } catch (_: Exception) {
      newFixedLengthResponse(Response.Status.INTERNAL_ERROR, MIME_HTML, null)
    }

  private fun postConfig(session: IHTTPSession): Response {
    return try {
      if (session.headers["x-suppress-dialog"] != "true" && !confirmOverwrite()) {
        return newFixedLengthResponse(Response.Status.UNAUTHORIZED, MIME_HTML, null)
      }
      val map = HashMap<String, String>()
      session.parseBody(map)
      val daoHub = Gson().fromJson(map["postData"], ConfigDaoHub::class.java)
      Database.getInstance().dropConfigs()
      daoHub.listenPortList.forEach { ListenPorts.getInstance().create(it) }
      daoHub.serverList.forEach { Servers.getInstance().create(it) }
      daoHub.modificationList.forEach { Modifications.getInstance().create(it) }
      daoHub.sslPassThroughList.forEach { SSLPassThroughs.getInstance().create(it) }
      newFixedLengthResponse(Response.Status.OK, "application/json", "{\"status\": \"ok\"}").apply {
        addHeader("Access-Control-Allow-Origin", "*")
      }
    } catch (_: Exception) {
      newFixedLengthResponse(Response.Status.INTERNAL_ERROR, MIME_HTML, null)
    }
  }

  private fun confirmOverwrite(): Boolean {
    val gui = GUIMain.getInstance()
    gui.isAlwaysOnTop = true
    gui.isVisible = true
    gui.tabbedPane.selectedIndex = GUIMain.Panes.OPTIONS.ordinal
    val option =
      JOptionPane.showConfirmDialog(
        gui,
        I18nString.get("Do you want to overwrite config?"),
        I18nString.get("Loading config"),
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE,
      )
    gui.isAlwaysOnTop = false
    return option != JOptionPane.NO_OPTION
  }

  private fun fixUp(daoHub: ConfigDaoHub) {
    val serverMap = hashMapOf(-1 to -1, 0 to 0)
    daoHub.serverList.forEachIndexed { index, server ->
      val id = index + 1
      serverMap[server.getId()] = id
      server.setId(id)
    }
    daoHub.listenPortList.forEachIndexed { index, listenPort ->
      listenPort.setServerId(serverMap[listenPort.getServerId()] ?: -1)
      listenPort.setId(index + 1)
    }
    daoHub.modificationList.forEachIndexed { index, modification ->
      modification.setServerId(serverMap[modification.getServerId()]!!)
      modification.setId(index + 1)
    }
  }
}
