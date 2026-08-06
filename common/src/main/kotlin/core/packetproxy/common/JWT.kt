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
package packetproxy.common

import java.io.ByteArrayInputStream
import java.util.HashMap
import net.arnx.jsonic.JSON
import packetproxy.util.asMutableStringKeyMap
import packetproxy.util.asStringKeyMap
import packetproxy.util.log

open class JWT {
  protected var header: String? = null
  protected var payload: String? = null

  constructor()

  constructor(jwt: JWT) {
    header = jwt.header
    payload = jwt.payload
  }

  constructor(jwtString: String) {
    val map: Map<String, Any?> = JSON.decode(ByteArrayInputStream(jwtString.toByteArray()))
    header = JSON.encode(map["header"])
    payload = JSON.encode(map["payload"])
  }

  fun getHeaderValue(keystr: String): String? = getValue(header, keystr)

  fun getPayloadValue(keystr: String): String? = getValue(payload, keystr)

  fun setHeaderValue(keystr: String, value: String) {
    header = setValue(header, keystr, value)
  }

  fun setPayloadValue(keystr: String, value: String) {
    payload = setValue(payload, keystr, value)
  }

  fun debug() {
    log(header ?: "null")
    log(payload ?: "null")
  }

  open fun toJwtString(): String =
    "{\n  header: ${createHeader(header)},\n  payload: ${createPayload(payload)}\n}"

  @Throws(Exception::class) protected open fun createSignature(input: String): String = "NotDefined"

  protected open fun createHeader(input: String?): String? = input

  protected open fun createPayload(input: String?): String? = input

  private fun getValue(chunk: String?, keystr: String): String? {
    val keys = keystr.split("/")
    var cur: Map<String, Any?>? = JSON().parse(chunk)
    for (i in 0 until keys.size - 1) {
      cur ?: return null
      cur = cur[keys[i]].asStringKeyMap()
    }
    return cur?.get(keys.last()) as? String
  }

  private fun setValue(chunk: String?, keystr: String, value: String): String {
    val keys = keystr.split("/")
    val root: MutableMap<String, Any?> = JSON().parse(chunk)
    var cur = root
    for (i in 0 until keys.size - 1) {
      val next =
        cur[keys[i]].asMutableStringKeyMap() ?: HashMap<String, Any?>().also { cur[keys[i]] = it }
      cur = next
    }
    cur[keys.last()] = value
    return JSON.encode(root)
  }
}
