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
package packetproxy.model

import com.j256.ormlite.field.DatabaseField
import com.j256.ormlite.table.DatabaseTable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import packetproxy.PrivateDNSClient
import packetproxy.util.Logging.err
import packetproxy.util.Logging.errWithStackTrace

@DatabaseTable(tableName = "servers")
open class Server {
  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField(uniqueCombo = true) private var ip: String? = null

  @field:DatabaseField(uniqueCombo = true) private var port = 0

  @field:DatabaseField(uniqueCombo = true) private var encoder: String? = null

  @field:DatabaseField private var use_ssl = false

  @field:DatabaseField private var resolved_by_dns = false

  @field:DatabaseField private var resolved_by_dns6 = false

  @field:DatabaseField private var http_proxy = false

  @field:DatabaseField private var comment: String? = null

  @field:DatabaseField(columnName = "descriptor_path") private var descriptorPath: String? = null

  private var specifiedByHostName = false

  constructor()

  constructor(ip: String, port: Int, encoder: String) {
    initialize(ip, port, false, encoder, false, false, false, "")
  }

  constructor(
    ip: String,
    port: Int,
    use_ssl: Boolean,
    encoder: String,
    resolved_by_dns: Boolean,
    resolved_by_dns6: Boolean,
    http_proxy: Boolean,
    comment: String,
  ) {
    initialize(ip, port, use_ssl, encoder, resolved_by_dns, resolved_by_dns6, http_proxy, comment)
  }

  private fun initialize(
    ip: String,
    port: Int,
    use_ssl: Boolean,
    encoder: String,
    resolved_by_dns: Boolean,
    resolved_by_dns6: Boolean,
    http_proxy: Boolean,
    comment: String,
  ) {
    this.ip = ip
    this.port = port
    this.use_ssl = use_ssl
    this.encoder = encoder
    this.resolved_by_dns = resolved_by_dns
    this.resolved_by_dns6 = resolved_by_dns6
    this.http_proxy = http_proxy
    this.comment = comment
    this.descriptorPath = null
    this.specifiedByHostName = isHostName(ip)
  }

  override fun toString(): String = String.format("%s:%d(%s)", ip, port, encoder)

  @Throws(Exception::class)
  fun getAddress(): InetSocketAddress = InetSocketAddress(PrivateDNSClient.getByName(ip!!), port)

  fun getId(): Int = this.id

  fun setId(id: Int) {
    this.id = id
  }

  fun getIp(): String? = this.ip

  fun setIp(ip: String) {
    this.ip = ip
  }

  fun getPort(): Int = port

  fun setPort(port: Int) {
    this.port = port
  }

  fun getEncoder(): String? = encoder

  fun setEncoder(encoder: String) {
    this.encoder = encoder
  }

  fun setUseSSL(ssl: Boolean) {
    this.use_ssl = ssl
  }

  fun getUseSSL(): Boolean = this.use_ssl

  fun setHttpProxy(http_proxy: Boolean) {
    this.http_proxy = http_proxy
  }

  fun isHttpProxy(): Boolean = this.http_proxy

  fun enableResolved() {
    this.resolved_by_dns = true
  }

  fun disableResolved() {
    this.resolved_by_dns = false
  }

  fun isResolved(): Boolean = this.resolved_by_dns

  fun setResolved(resolved_by_dns: Boolean) {
    this.resolved_by_dns = resolved_by_dns
  }

  fun enableResolved6() {
    this.resolved_by_dns6 = true
  }

  fun disableResolved6() {
    this.resolved_by_dns6 = false
  }

  fun isResolved6(): Boolean = this.resolved_by_dns6

  fun setResolved6(resolved_by_dns6: Boolean) {
    this.resolved_by_dns6 = resolved_by_dns6
  }

  fun getComment(): String? = this.comment

  fun setComment(comment: String) {
    this.comment = comment
  }

  fun getDescriptorPath(): String? = descriptorPath

  fun setDescriptorPath(descriptorPath: String?) {
    this.descriptorPath = descriptorPath
  }

  fun getIps(): List<InetAddress> {
    try {
      if (specifiedByHostName) {
        return PrivateDNSClient.getAllByName(ip!!).toList()
      } else {
        val ips = ArrayList<InetAddress>()
        ips.add(InetAddress.getByName(ip!!))
        return ips
      }
    } catch (e: UnknownHostException) {
      err("Nonexistent server '%s' is specified in config [DNS resolv error]", ip)
      return ArrayList()
    } catch (e: Exception) {
      // TODO Auto-generated catch block
      errWithStackTrace(e)
      return ArrayList()
    }
  }

  companion object {
    private fun isHostName(host: String): Boolean {
      try {
        return !(InetAddress.getByName(host).hostAddress == host)
      } catch (e: UnknownHostException) {
        errWithStackTrace(e)
        return true
      }
    }
  }
}
