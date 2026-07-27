/*
 * Copyright 2022 DeNA Co., Ltd.
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

import java.net.InetAddress
import java.net.UnknownHostException
import java.nio.file.Files
import java.nio.file.Paths
import org.xbill.DNS.AAAARecord
import org.xbill.DNS.Address
import org.xbill.DNS.Lookup
import org.xbill.DNS.Record
import org.xbill.DNS.ResolverConfig
import org.xbill.DNS.TextParseException
import org.xbill.DNS.Type
import packetproxy.model.PrivateDnsHooks
import packetproxy.model.Resolutions
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.Logging.log
import packetproxy.util.PacketProxyUtility

object PrivateDNSClient {
  private var resolutions: Resolutions? = null

  private fun isLoopbackAddress(addr: String): Boolean =
    addr == "127.0.0.1" || addr == "0:0:0:0:0:0:0:1" || addr == "::1"

  @Throws(UnknownHostException::class)
  private fun isLocalAddress(addr: String): Boolean {
    val localAddr = InetAddress.getLocalHost().hostAddress
    return addr == localAddr
  }

  @Throws(Exception::class)
  private fun dnsLooping(serverName: String): Boolean =
    dnsLoopDetectedInDnsServer() || dnsLoopDetectedInEtcHosts(serverName)

  @JvmStatic
  fun getCurrentSystemDnsServerAddress(): String? {
    ResolverConfig.refresh()
    val resolverConfig = ResolverConfig.getCurrentConfig() ?: return null
    if (resolverConfig.server() == null) {
      return null
    }
    return resolverConfig.server().address.hostAddress
  }

  // システムのDNS設定が、PacketProxyのDNSサーバが設定されているときtrueになる
  @Throws(Exception::class)
  private fun dnsLoopDetectedInDnsServer(): Boolean {
    if (!PrivateDnsHooks.isRunning()) {
      return false
    }

    // current system dns server setting
    val dnsServer = getCurrentSystemDnsServerAddress() ?: return false

    if (isLoopbackAddress(dnsServer)) {
      return true
    }
    if (isLocalAddress(dnsServer)) {
      return true
    }
    return false
  }

  @JvmStatic
  @Throws(Exception::class)
  fun dnsLoopDetectedInEtcHosts(serverName: String): Boolean =
    if (PacketProxyUtility.getInstance().isMac() || PacketProxyUtility.getInstance().isUnix()) {
      dnsLoopingFromHostsLines(Files.readAllLines(Paths.get("/etc/hosts")), serverName)
    } else {
      false
    }

  @JvmStatic
  fun dnsLoopingFromHostsLines(fileLines: List<String>, serverName: String): Boolean =
    fileLines
      .map { line -> if (line.contains("#")) line.substring(0, line.indexOf('#')) else line }
      .filter { line -> line.contains(serverName) }
      .any { line ->
        try {
          val addr = line.split(" ")[0]
          if (isLoopbackAddress(addr) || isLocalAddress(addr)) {
            return@any true
          }
        } catch (e: Exception) {
          errWithStackTrace(e)
        }
        false
      }

  @JvmStatic
  @Throws(Exception::class)
  fun getByName(serverName: String): InetAddress {
    resolutions = Resolutions.getInstance()
    val resolution_list = resolutions!!.queryEnabled()
    for (resolution in resolution_list) {
      if (serverName == resolution.getHostName()) {
        val ip = resolution.getIp()
        log("[Hostname Resolution]: %s -> %s", serverName, ip)
        return InetAddress.getByName(ip)
      }
    }
    if (serverName == "localhost") {
      return InetAddress.getByName(serverName)
    }
    return if (dnsLooping(serverName)) Address.getByName(serverName)
    else InetAddress.getByName(serverName)
  }

  @JvmStatic
  @Throws(Exception::class)
  fun getAllByName(serverName: String): Array<InetAddress> {
    if (serverName == "localhost") {
      return InetAddress.getAllByName(serverName)
    }
    return if (dnsLooping(serverName)) Address.getAllByName(serverName)
    else InetAddress.getAllByName(serverName)
  }

  @JvmStatic
  fun getByName6(host: String): InetAddress? {
    val hostIP: InetAddress?
    try {
      val lookup = Lookup(host, Type.AAAA)
      // lookup.setResolver(resolver);
      val records = lookup.run()
      if (records == null) {
        return null
      }
      hostIP = (records[0] as AAAARecord).address
    } catch (ex: TextParseException) {
      log("'%s'", ex.message)
      throw IllegalStateException(ex)
    }
    return hostIP
  }

  @JvmStatic
  @Throws(Exception::class)
  fun getHTTPSRecord(host: String): Array<Record>? {
    val lookup = Lookup(host, Type.HTTPS)
    return lookup.run()
  }
}
