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
import packetproxy.common.Binary
import packetproxy.common.Binary.HexString
import packetproxy.common.Utils

@DatabaseTable(tableName = "interceptOptions")
class InterceptOption {
  enum class Type {
    REQUEST
    /* HOST / URL intercept types are unsupported */
  }

  enum class Direction {
    REQUEST,
    RESPONSE,
    ALL_THE_OTHER_REQUESTS,
    ALL_THE_OTHER_RESPONSES,
  } // 両方同じルールで捕まえたい事はないのでALLは無し

  enum class Relationship {
    IS_INTERCEPTED_IF_IT_MATCHES,
    IS_INTERCEPTED_IF_REQUEST_WAS_INTERCEPTED,
    IS_NOT_INTERCEPTED_IF_IT_MATCHES,
    ARE_INTERCEPTED,
    ARE_NOT_INTERCEPTED,
  }

  enum class Method {
    SIMPLE,
    REGEX,
    BINARY,
    UNDEFINED,
  }

  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField private var enabled: Boolean? = null

  @field:DatabaseField(uniqueCombo = true) private var direction: Direction? = null

  @field:DatabaseField(uniqueCombo = true) private var type: Type? = null

  @field:DatabaseField(uniqueCombo = true) private var relationship: Relationship? = null

  @field:DatabaseField(uniqueCombo = true) private var method: Method? = null

  @field:DatabaseField(uniqueCombo = true) private var pattern: String? = null

  @field:DatabaseField(uniqueCombo = true) private var server_id = 0

  constructor()

  constructor(
    direction: Direction,
    type: Type,
    relationship: Relationship,
    pattern: String,
    method: Method,
    server: Server?,
  ) {
    this.enabled = true
    this.direction = direction
    this.type = type
    this.relationship = relationship
    this.method = method
    this.pattern = pattern
    this.server_id = if (server != null) server.getId() else ALL_SERVER
  }

  fun setId(id: Int) {
    this.id = id
  }

  fun isEnabled(): Boolean = this.enabled ?: false

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

  @Throws(Exception::class)
  fun getServer(database: Database): Server? =
    database.createTable<Server, Int>(Server::class.java).queryForId(this.server_id)

  @Throws(Exception::class)
  fun getServerName(database: Database): String {
    if (this.server_id == ALL_SERVER) {
      return "*"
    }
    val server = getServer(database)
    return if (server != null) server.toString() else ""
  }

  fun getDirection(): Direction? = this.direction

  fun getDirectionAsString(): String = getDirectionAsString(this.direction)

  fun setDirection(direction: Direction) {
    this.direction = direction
  }

  fun isDirection(direction: Direction): Boolean = this.direction == direction

  fun getType(): Type? = this.type

  fun setType(type: Type) {
    this.type = type
  }

  fun getRelationship(): Relationship? = this.relationship

  fun getRelationshipAsString(): String = getRelationshipAsString(this.relationship)

  fun isRelationship(relationshipStr: String): Boolean =
    relationshipStr == getRelationshipAsString()

  fun setRelationship(relationship: Relationship) {
    this.relationship = relationship
  }

  fun getMethod(): Method? = this.method

  fun getMethodAsString(): String =
    when (this.method) {
      Method.SIMPLE -> "SIMPLE"
      Method.REGEX -> "REGEX"
      Method.BINARY -> "BINARY"
      else -> ""
    }

  fun setMethod(method: Method) {
    this.method = method
  }

  fun getPattern(): String? = this.pattern

  fun setPattern(pattern: String) {
    this.pattern = pattern
  }

  fun getId(): Int = id

  @Throws(Exception::class)
  fun match(client_packet: Packet?, server_packet: Packet?): Boolean {
    assert(this.relationship != Relationship.IS_INTERCEPTED_IF_REQUEST_WAS_INTERCEPTED)
    assert(this.relationship != Relationship.ARE_INTERCEPTED)
    assert(this.relationship != Relationship.ARE_NOT_INTERCEPTED)
    var data: ByteArray? = null
    if (this.direction == Direction.REQUEST) {
      assert(client_packet != null)
      data = client_packet!!.getDecodedData()
    } else if (this.direction == Direction.RESPONSE) {
      assert(server_packet != null)
      data = server_packet!!.getDecodedData()
    }
    if (data == null) {
      return false
    }
    // Type values other than REQUEST are unsupported; match against full packet bytes.
    val result =
      if (method == Method.SIMPLE) {
        matchText(data)
      } else if (method == Method.REGEX) {
        matchRegex(data)
      } else if (method == Method.BINARY) {
        matchBinary(data)
      } else {
        matchText(data)
      }
    return result
  }

  private fun matchText(data: ByteArray): Boolean = matchBinary(data, pattern!!.toByteArray())

  private fun matchRegex(data: ByteArray): Boolean {
    val pattern = Pattern.compile(this.pattern!!, Pattern.MULTILINE)
    val matcher = pattern.matcher(String(data))
    return matcher.find()
  }

  @Throws(Exception::class)
  private fun matchBinary(data: ByteArray): Boolean {
    val binPattern = Binary(HexString(pattern!!)).toByteArray()
    return matchBinary(data, binPattern)
  }

  private fun matchBinary(data: ByteArray, binPattern: ByteArray): Boolean =
    Utils.indexOf(data, 0, data.size, binPattern) >= 0

  override fun hashCode(): Int = this.getId()

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is InterceptOption) return false
    return this.getId() == other.getId()
  }

  companion object {
    const val ALL_SERVER = -1

    @JvmStatic
    fun getDirection(directionStr: String): Direction {
      for (d in Direction.values()) {
        if (getDirectionAsString(d) == directionStr) {
          return d
        }
      }
      return Direction.REQUEST
    }

    @JvmStatic
    fun getDirectionAsString(direction: Direction?): String =
      when (direction) {
        Direction.REQUEST -> "Request"
        Direction.RESPONSE -> "Response"
        Direction.ALL_THE_OTHER_REQUESTS -> "All the other requests"
        Direction.ALL_THE_OTHER_RESPONSES -> "All the other responses"
        else -> "Request"
      }

    @JvmStatic
    fun getRelationship(relationshipStr: String): Relationship {
      for (r in Relationship.values()) {
        if (getRelationshipAsString(r) == relationshipStr) {
          return r
        }
      }
      return Relationship.IS_INTERCEPTED_IF_IT_MATCHES
    }

    @JvmStatic
    fun getRelationshipAsString(relationship: Relationship?): String =
      when (relationship) {
        Relationship.IS_INTERCEPTED_IF_IT_MATCHES -> "is intercepted if it matches"
        Relationship.IS_INTERCEPTED_IF_REQUEST_WAS_INTERCEPTED ->
          "is intercepted if request was intercepted"
        Relationship.IS_NOT_INTERCEPTED_IF_IT_MATCHES -> "is not intercepted if it matches"
        Relationship.ARE_INTERCEPTED -> "are intercepted"
        Relationship.ARE_NOT_INTERCEPTED -> "are not intercepted"
        else -> "is intercepted if it matches"
      }
  }
}
