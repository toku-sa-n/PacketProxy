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
package packetproxy.encode

import net.arnx.jsonic.JSON
import packetproxy.model.Packet

class EncodeFirebase @Throws(Exception::class) constructor(ALPN: String?) :
  EncodeHTTPWebSocket(ALPN) {
  override fun getName(): String = "FirebaseDB"

  override fun getSummarizedRequest(packet: Packet): String {
    val raw_data =
      if (packet.getDecodedData().isNotEmpty()) packet.getDecodedData()
      else packet.getModifiedData()
    val data = String(raw_data)
    try {
      val json: Map<String, Map<String, Any?>> = JSON.decode(data)
      val a = json["d"]!!["a"].toString()

      var action = "UNKNOWN"
      when (a) {
        "n" -> action = "DELETE"
        "q" -> action = "READ"
        "p" -> action = "WRITE"
      }

      val id = json["d"]!!["r"].toString()
      val b = json["d"]!!["b"] as Map<*, *>

      if (a == "auth") {
        return id + "LOGIN BY" + b["cred"]
      }

      val path = b["p"].toString()

      return listOf(id, action, path).joinToString(" ")
    } catch (e: Exception) {
      return data
    }
  }

  override fun getSummarizedResponse(packet: Packet): String {
    val raw_data =
      if (packet.getDecodedData().isNotEmpty()) packet.getDecodedData()
      else packet.getModifiedData()
    val data = String(raw_data)
    try {
      val json: Map<String, Map<String, Any?>> = JSON.decode(data)
      val d = json["d"] as Map<*, *>
      if (d.containsKey("r")) {
        return d["r"].toString() + d["b"].toString()
      }
      val b = json["d"]!!["b"] as Map<*, *>
      var path = b["p"]?.toString()
      if (path == null) path = ""
      return "FETCHED: $path"
    } catch (e: Exception) {
      return data
    }
  }
}
