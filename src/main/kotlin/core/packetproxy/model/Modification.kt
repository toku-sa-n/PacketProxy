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

import com.google.re2j.Pattern
import com.j256.ormlite.field.DatabaseField
import com.j256.ormlite.table.DatabaseTable
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.Binary
import packetproxy.common.Binary.HexString
import packetproxy.common.Utils

@DatabaseTable(tableName = "modifications")
class Modification {
  enum class Direction {
    CLIENT_REQUEST,
    SERVER_RESPONSE,
    ALL,
  }

  enum class Method {
    SIMPLE,
    REGEX,
    BINARY,
  }

  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField private var enabled: Boolean? = null

  @field:DatabaseField(uniqueCombo = true) private var server_id = 0

  @field:DatabaseField(uniqueCombo = true) private var direction: Direction? = null

  @field:DatabaseField(uniqueCombo = true) private var pattern: String? = null

  @field:DatabaseField(uniqueCombo = true) private var method: Method? = null

  @field:DatabaseField private var replaced: String? = null

  constructor()

  constructor(
    direction: Direction,
    pattern: String,
    replaced: String,
    method: Method,
    server: Server?,
  ) {
    this.enabled = false
    this.server_id = if (server != null) server.getId() else ALL_SERVER
    this.direction = direction
    this.pattern = pattern
    this.replaced = replaced
    this.method = method
  }

  fun isEnabled(): Boolean = this.enabled!!

  fun setEnabled() {
    this.enabled = true
  }

  fun setDisabled() {
    this.enabled = false
  }

  fun getServerId(): Int = this.server_id

  fun setServerId(server_id: Int) {
    this.server_id = server_id
  }

  @Throws(Exception::class) fun getServer(): Server? = Servers.getInstance().query(this.server_id)

  @Throws(Exception::class)
  fun getServerName(): String {
    if (this.server_id == ALL_SERVER) {
      return "*"
    }
    val server = Servers.getInstance().query(this.server_id)
    return if (server != null) server.toString() else ""
  }

  fun getDirection(): Direction? = this.direction

  fun setDirection(direction: Direction) {
    this.direction = direction
  }

  fun getPattern(): String? = this.pattern

  fun setPattern(pattern: String) {
    this.pattern = pattern
  }

  fun getReplaced(): String? = this.replaced

  fun setReplaced(replaced: String) {
    this.replaced = replaced
  }

  fun getMethod(): Method? = this.method

  fun setMethod(method: Method) {
    this.method = method
  }

  fun getId(): Int = id

  fun setId(id: Int) {
    this.id = id
  }

  @Throws(Exception::class)
  fun replace(data: ByteArray, packet: Packet): ByteArray {
    if (method == Method.SIMPLE) {
      return replaceText(data, packet)
    } else if (method == Method.REGEX) {
      return replaceRegex(data, packet)
    } else if (method == Method.BINARY) {
      return replaceBinary(data, packet)
    } else {
      throw Exception("未定義の置換方法")
    }
  }

  private fun replaceText(data: ByteArray, packet: Packet): ByteArray =
    replaceBinary(data, pattern!!.toByteArray(), replaced!!.toByteArray(), packet)

  private fun replaceRegex(data: ByteArray, packet: Packet): ByteArray {
    val pattern = Pattern.compile(this.pattern!!, Pattern.MULTILINE)
    val matcher = pattern.matcher(String(data))
    var result = String(data)
    var matched = false
    while (matcher.find()) {
      matched = true
      result = matcher.replaceAll(this.replaced)
      packet.setModified()
    }
    if (!matched) {
      // バイナリデータが壊れる可能性があるので、マッチしなかった場合はそのまま返す
      return data
    }
    return result.toByteArray()
  }

  @Throws(Exception::class)
  private fun replaceBinary(data: ByteArray, packet: Packet): ByteArray {
    val binPattern = Binary(HexString(pattern!!)).toByteArray()
    val binReplaced = Binary(HexString(replaced!!)).toByteArray()
    return replaceBinary(data, binPattern, binReplaced, packet)
  }

  private fun replaceBinary(
    data: ByteArray,
    binPattern: ByteArray,
    binReplaced: ByteArray,
    packet: Packet,
  ): ByteArray {
    var data = data
    var idx = 0
    while (idx < data.size) {
      idx = Utils.indexOf(data, idx, data.size, binPattern)
      if (idx < 0) {
        return data
      }
      val front_data = ArrayUtils.subarray(data, 0, idx)
      val back_data = ArrayUtils.subarray(data, idx + binPattern.size, data.size)
      data = ArrayUtils.addAll(front_data, *binReplaced)
      data = ArrayUtils.addAll(data, *back_data)
      idx += binReplaced.size
      packet.setModified()
    }
    return data
  }

  override fun hashCode(): Int = this.getId()

  fun equals(obj: Modification): Boolean = if (this.getId() == obj.getId()) true else false

  companion object {
    const val ALL_SERVER = -1
  }
}
