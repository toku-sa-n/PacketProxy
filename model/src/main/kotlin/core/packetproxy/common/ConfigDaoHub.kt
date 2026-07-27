package packetproxy.common

import com.google.gson.annotations.SerializedName
import packetproxy.model.ListenPort
import packetproxy.model.Modification
import packetproxy.model.SSLPassThrough
import packetproxy.model.Server

class ConfigDaoHub {
  @SerializedName("listenPorts") lateinit var listenPortList: List<ListenPort>

  @SerializedName("servers") lateinit var serverList: List<Server>

  @SerializedName("modifications") lateinit var modificationList: List<Modification>

  @SerializedName("sslPassThroughs") lateinit var sslPassThroughList: List<SSLPassThrough>
}
