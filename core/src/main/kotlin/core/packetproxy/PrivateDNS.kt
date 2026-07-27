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
package packetproxy

import java.io.IOException
import java.net.BindException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketException
import java.net.UnknownHostException
import java.util.Collections
import org.apache.commons.net.util.SubnetUtils
import org.apache.commons.net.util.SubnetUtils.SubnetInfo
import org.xbill.DNS.DClass
import org.xbill.DNS.HTTPSRecord
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.SVCBBase
import org.xbill.DNS.Type
import packetproxy.model.ConfigBoolean
import packetproxy.model.ConfigInteger
import packetproxy.model.PrivateDnsHooks
import packetproxy.model.PrivateDnsRunningCheck
import packetproxy.model.Servers
import packetproxy.util.Logging.err
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.Logging.log

class PrivateDNS private constructor() {
  companion object {
    var BUFSIZE = 1024
    var DEFAULT_PORT = 53
    var dnsServer = "8.8.8.8"
    private var instance: PrivateDNS? = null

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): PrivateDNS {
      if (instance == null) {
        instance = PrivateDNS()
        PrivateDnsHooks.runningCheck = PrivateDnsRunningCheck { instance!!.isRunning() }
      }
      return instance!!
    }
  }

  private val state: ConfigBoolean
  private var dns: PrivateDNSImp? = null
  private val servers: Servers
  private val lock: Any
  private val spoofAddrFactry = SpoofAddrFactory()

  inner class SpoofAddrFactory {
    private val subnets = ArrayList<SubnetInfo>()
    private val ifscopes = HashMap<Int, Inet6Address>()
    private var defaultAddr: String? = null
    private var defaultAddr6: Inet6Address? = null

    init {
      val nets = NetworkInterface.getNetworkInterfaces()
      for (netint in Collections.list(nets)) {
        for (intAddress in netint.interfaceAddresses) {
          val addr = intAddress.address
          if (addr is Inet4Address) {
            val length = intAddress.networkPrefixLength
            if (length < 0) continue
            val cidr = String.format("%s/%d", addr.hostAddress, length)
            val subnet = SubnetUtils(cidr)
            subnets.add(subnet.info)
            if (defaultAddr == null) {
              defaultAddr = addr.hostAddress
            } else if (defaultAddr == "127.0.0.1") {
              defaultAddr = addr.hostAddress
            }
          } else {
            if (!addr.isMulticastAddress && !addr.isLinkLocalAddress && !addr.isSiteLocalAddress) {
              ifscopes[(addr as Inet6Address).scopeId] = addr
              if (defaultAddr6 == null) {
                defaultAddr6 = addr
              } else if (defaultAddr6!!.isLoopbackAddress) {
                defaultAddr6 = addr
              }
            }
          }
        }
      }
    }

    fun getSpoofAddr(addr: InetAddress): Map<Int, String> {
      val spoofAddrs = HashMap<Int, String>()
      if (addr is Inet4Address) {
        for (subnet in subnets) {
          if (subnet.isInRange(addr.hostAddress)) {
            spoofAddrs[4] = subnet.address
          }
        }
        if (spoofAddrs[4] == null) {
          spoofAddrs[4] = defaultAddr!!
        }
        spoofAddrs[6] = defaultAddr6!!.hostAddress
      } else {
        if (ifscopes.containsKey((addr as Inet6Address).scopeId)) {
          spoofAddrs[6] = ifscopes[addr.scopeId]!!.hostAddress
        } else {
          spoofAddrs[6] = defaultAddr6!!.hostAddress
        }
        spoofAddrs[4] = defaultAddr!!
      }
      return spoofAddrs
    }
  }

  init {
    lock = Any()
    state = ConfigBoolean("PrivateDNS")
    servers = Servers.getInstance()
    dns = null
  }

  @Throws(Exception::class) fun isRunning(): Boolean = state.getState()

  fun start(dnsSpoofingIPGetter: DNSSpoofingIPGetter): Boolean {
    synchronized(lock) {
      if (dns == null) {
        try {
          dns = PrivateDNSImp(dnsSpoofingIPGetter)
          if (dns!!.isRunning()) {
            dns!!.start()
            state.setState(true)
          } else {
            dns = null
            state.setState(false)
            return false
          }
        } catch (e: Exception) {
          errWithStackTrace(e)
          dns = null
          try {
            state.setState(false)
          } catch (ignored: Exception) {}
          return false
        }
      }
    }
    return true
  }

  fun restart(dnsSpoofingIPGetter: DNSSpoofingIPGetter): Boolean {
    synchronized(lock) {
      if (dns != null) {
        dns!!.finish()
        dns = null
      }

      try {
        dns = PrivateDNSImp(dnsSpoofingIPGetter)
        if (dns!!.isRunning()) {
          dns!!.start()
          state.setState(true)
        } else {
          dns = null
          state.setState(false)
          return false
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
        dns = null
        try {
          state.setState(false)
        } catch (ignored: Exception) {}
        return false
      }
    }
    return true
  }

  fun getConfiguredPort(): Int = getListenPort()

  fun isPortChangeNeeded(port: Int): Boolean {
    if (!isValidPort(port)) {
      return false
    }
    return port != getListenPort()
  }

  fun isPortInRange(port: Int): Boolean = isValidPort(port)

  fun setPort(port: Int, dnsSpoofingIPGetter: DNSSpoofingIPGetter?) {
    if (!isValidPort(port)) {
      return
    }
    synchronized(lock) {
      try {
        val portConfig = ConfigInteger("PrivateDNSPort")
        val currentPort = portConfig.getInteger()
        if (currentPort != port) {
          log("Private DNS port changed: %d -> %d", currentPort, port)
          portConfig.setInteger(port)
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
        return
      }
    }

    if (dnsSpoofingIPGetter == null) {
      return
    }

    try {
      if (isRunning() && !restart(dnsSpoofingIPGetter)) {
        state.setState(false)
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  fun stop() {
    synchronized(lock) {
      if (dns != null) {
        dns!!.finish()
        dns = null
        try {
          state.setState(false)
        } catch (e: Exception) {
          errWithStackTrace(e)
        }
      }
    }
  }

  private inner class PrivateDNSImp(dnsSpoofingIPGetter: DNSSpoofingIPGetter) : Thread() {
    private val spoofingIp: DNSSpoofingIPGetter = dnsSpoofingIPGetter
    private val listenPort: Int = getListenPort()

    private var cAddr: InetAddress? = null
    private var cPort: Int = 0
    private val buf = ByteArray(BUFSIZE)
    var soc: DatagramSocket? = null
    var recvPacket: DatagramPacket? = null
    var sendPacket: DatagramPacket? = null
    var s_soc: DatagramSocket? = null
    var s_recvPacket: DatagramPacket? = null
    var s_sendPacket: DatagramPacket? = null
    var s_sAddr: InetAddress? = null

    init {
      try {
        soc = DatagramSocket(listenPort, InetAddress.getByName(spoofingIp.getInt()))
        recvPacket = DatagramPacket(buf, BUFSIZE)
        sendPacket = null
        s_sAddr = InetAddress.getByName(dnsServer)
        s_soc = DatagramSocket()
        s_recvPacket = DatagramPacket(buf, BUFSIZE)
        s_sendPacket = null
      } catch (e: BindException) {
        err(
          "cannot boot private DNS server (permission issue or already listened): addr=%s port=%d",
          spoofingIp.getInt(),
          listenPort,
        )
      }
    }

    fun isRunning(): Boolean = soc != null

    fun finish() {
      if (isRunning()) {
        s_soc!!.close()
        soc!!.close()
        s_soc = null
        soc = null
      }
    }

    override fun run() {
      log("Private DNS Server started. (addr=%s port=%d)", spoofingIp.getInt(), listenPort)
      while (true) {
        try {
          soc!!.receive(recvPacket)
          cAddr = recvPacket!!.address
          cPort = recvPacket!!.port

          var spoofingIpStrs: Map<Int, String> = HashMap()
          var spoofingIpStr = ""
          var spoofingIp6Str = ""

          if (spoofingIp.isAuto()) {
            spoofingIpStrs = spoofAddrFactry.getSpoofAddr(cAddr!!)
            spoofingIpStr = spoofingIpStrs[4]!!
            spoofingIp6Str = spoofingIpStrs[6]!!
          } else {
            spoofingIpStr = spoofingIp.get()
            spoofingIp6Str = spoofingIp.get6()
          }

          val requestData = recvPacket!!.data

          val smsg = Message(requestData)
          val smsgBA = smsg.toWire()
          val queryRecType = smsg.question.type
          val queryHostName = smsg.question.getName().toString(true)
          val queryRecTypeName = Type.string(queryRecType)
          val addr: InetAddress
          var res: ByteArray? = null

          try {
            if (queryRecType == Type.A) {
              addr = PrivateDNSClient.getByName(queryHostName)
              if (addr is Inet6Address) {
                throw UnknownHostException()
              }
            } else if (queryRecType == Type.AAAA) {
              addr = PrivateDNSClient.getByName6(queryHostName) ?: throw UnknownHostException()
            } else if (queryRecType == Type.HTTPS) {
              log("[DNS Query] '%s' [HTTPS]", queryHostName)
              val jn: PrivateDnsResponseBuilder
              if (isTargetHost(queryHostName)) {
                val label = Name.fromString("$queryHostName.")
                val svcDomain = Name.fromString(".")
                val alpn = SVCBBase.ParameterAlpn()
                alpn.fromString("h1,h2,h3")
                val params = listOf<SVCBBase.ParameterBase>(alpn)
                val record = HTTPSRecord(label, DClass.IN, 300, 1, svcDomain, params)
                jn = PrivateDnsResponseBuilder(record)
                log("Force to access '%s' with HTTP3", queryHostName)
              } else {
                val records = PrivateDNSClient.getHTTPSRecord(queryHostName)
                jn = PrivateDnsResponseBuilder(records)
              }
              res = jn.generateReply(smsg, smsgBA, smsgBA.size, null)
              sendPacket = DatagramPacket(res!!, res.size, cAddr, cPort)
              soc!!.send(sendPacket)
              continue
            } else {
              log("[DNS Query] Unsupported Query Type: '%s' [%s]", queryHostName, queryRecTypeName)
              throw UnsupportedOperationException()
            }

            var ip = addr.hostAddress

            log("[DNS Query] '%s' [%s]", queryHostName, queryRecTypeName)

            if (isTargetHost(queryHostName)) {
              if (queryRecType == Type.A) {
                // ToDo GUIにIPv4有効チェックを追加し、無効のときはスキップするようにする。
                ip = spoofingIpStr
                log("Replaced to %s", ip)
              }
            }
            if (isTargetHost6(queryHostName)) {
              if (queryRecType == Type.AAAA) {
                // ToDo GUIにIPv6有効チェックを追加し、無効のときはスキップするようにする。
                ip = spoofingIp6Str
                log("Replaced to %s", ip)
              }
            }
            val jn = PrivateDnsResponseBuilder(ip)
            res = jn.generateReply(smsg, smsgBA, smsgBA.size, null)
          } catch (e: UnknownHostException) {
            err("[DNS Query] Unknown Host: '%s' [%s]", queryHostName, queryRecTypeName)
            val jn = PrivateDnsResponseBuilder()
            res = jn.generateReply(smsg, smsgBA, smsgBA.size, null)
          } catch (e: UnsupportedOperationException) {
            // Not implemented yet
            val jn = PrivateDnsResponseBuilder()
            res = jn.generateReply(smsg, smsgBA, smsgBA.size, null)
          } catch (e: Exception) {
            err("[DNS Query] Unknown Error: '%s' [%s]", queryHostName, queryRecTypeName)
            val jn = PrivateDnsResponseBuilder()
            res = jn.generateReply(smsg, smsgBA, smsgBA.size, null)
          }
          sendPacket = DatagramPacket(res!!, res.size, cAddr, cPort)
          soc!!.send(sendPacket)
        } catch (e: SocketException) {
          if (soc == null || soc!!.isClosed) {
            finish()
            return
          }
          errWithStackTrace(e)
          finish()
          return
        } catch (e: IOException) {
          errWithStackTrace(e)
        } catch (e: Exception) {
          errWithStackTrace(e)
          finish()
          return
        }
      }
    }

    @Throws(Exception::class)
    private fun isTargetHost(hostName: String): Boolean {
      val server_list = servers.queryResolvedByDNS()
      for (server in server_list) {
        if (hostName == server.getIp()) {
          return true
        }
      }
      return false
    }

    @Throws(Exception::class)
    private fun isTargetHost6(hostName: String): Boolean {
      val server_list = servers.queryResolvedByDNS6()
      for (server in server_list) {
        if (hostName == server.getIp()) {
          return true
        }
      }
      return false
    }
  }

  private fun getListenPort(): Int {
    try {
      val portConfig = ConfigInteger("PrivateDNSPort")
      val port = portConfig.getInteger()
      if (isValidPort(port)) {
        return port
      }
      portConfig.setInteger(DEFAULT_PORT)
      return DEFAULT_PORT
    } catch (e: Exception) {
      errWithStackTrace(e)
      return DEFAULT_PORT
    }
  }

  private fun isValidPort(port: Int): Boolean = port in 1..65535
}
