package packetproxy.common

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import packetproxy.model.Database
import packetproxy.model.ListenPorts
import packetproxy.model.Modifications
import packetproxy.model.SSLPassThroughs
import packetproxy.model.Servers

class ConfigIO {
  @Throws(Exception::class)
  fun getOptions(): String {
    val daoHub =
      ConfigDaoHub().apply {
        listenPortList = ListenPorts.getInstance().queryAll()
        serverList = Servers.getInstance().queryAll()
        modificationList = Modifications.getInstance().queryAll()
        sslPassThroughList = SSLPassThroughs.getInstance().queryAll()
      }
    fixUp(daoHub)
    return GsonBuilder().setPrettyPrinting().create().toJson(daoHub)
  }

  @Throws(Exception::class)
  fun setOptions(json: String) {
    val daoHub = Gson().fromJson(json, ConfigDaoHub::class.java)
    Database.getInstance().dropConfigs()
    daoHub.listenPortList.forEach { ListenPorts.getInstance().create(it) }
    daoHub.serverList.forEach { Servers.getInstance().create(it) }
    daoHub.modificationList.forEach { Modifications.getInstance().create(it) }
    daoHub.sslPassThroughList.forEach { SSLPassThroughs.getInstance().create(it) }
  }

  private fun fixUp(daoHub: ConfigDaoHub) {
    val serverMap = HashMap<Int, Int>()
    fixUpServerList(serverMap, daoHub.serverList)
    fixUpListenPortList(serverMap, daoHub.listenPortList)
    fixUpModificationList(serverMap, daoHub.modificationList)
  }

  private fun fixUpServerList(
    serverMap: MutableMap<Int, Int>,
    serverList: List<packetproxy.model.Server>,
  ) {
    serverMap[-1] = -1
    serverMap[0] = 0
    serverList.forEachIndexed { index, server ->
      val id = index + 1
      serverMap[server.getId()] = id
      server.setId(id)
    }
  }

  private fun fixUpListenPortList(
    serverMap: Map<Int, Int>,
    listenPortList: List<packetproxy.model.ListenPort>,
  ) {
    listenPortList.forEachIndexed { index, listenPort ->
      listenPort.setServerId(serverMap[listenPort.getServerId()] ?: -1)
      listenPort.setId(index + 1)
    }
  }

  private fun fixUpModificationList(
    serverMap: Map<Int, Int>,
    modificationList: List<packetproxy.model.Modification>,
  ) {
    modificationList.forEachIndexed { index, modification ->
      modification.setServerId(serverMap[modification.getServerId()]!!)
      modification.setId(index + 1)
    }
  }
}
