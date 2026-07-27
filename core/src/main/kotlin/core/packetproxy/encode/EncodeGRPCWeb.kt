/*
 * Copyright 2019 shioshiota
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

import java.util.Optional
import net.arnx.jsonic.JSON
import packetproxy.common.GRPCMessage
import packetproxy.http.Http

open class EncodeGRPCWeb @Throws(Exception::class) constructor(ALPN: String?) :
  EncodeHTTPBase(ALPN) {
  override fun getName(): String = "gRPC-Web"

  @Throws(Exception::class)
  override fun decodeServerResponseHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (contentType.startsWith("application/grpc-web")) {
      var json = Optional.empty<String>()
      if (contentType.endsWith("web-text") || contentType.endsWith("web-text+proto")) {
        val base64Body = String(inputHttp.body)
        json = Optional.of(JSON.encode(GRPCMessage.decodeTextMessages(base64Body)))
      } else if (contentType.endsWith("web") || contentType.endsWith("web+proto")) {
        json = Optional.of(JSON.encode(GRPCMessage.decodeMessages(inputHttp.body)))
      }
      json.ifPresent { j -> inputHttp.setBody(j.toByteArray()) }
    }
    return inputHttp
  }

  @Throws(Exception::class)
  override fun encodeServerResponseHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (contentType.startsWith("application/grpc-web")) {
      val json: List<Map<String, Any?>> = JSON.decode(String(inputHttp.body))
      if (contentType.endsWith("web-text") || contentType.endsWith("web-text+proto")) {
        inputHttp.setBody(GRPCMessage.encodeTextMessages(json).toByteArray())
      } else if (contentType.endsWith("web") || contentType.endsWith("web+proto")) {
        inputHttp.setBody(GRPCMessage.encodeMessages(json))
      }
    }
    return inputHttp
  }

  @Throws(Exception::class)
  override fun decodeClientRequestHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (contentType.startsWith("application/grpc-web")) {
      var json = Optional.empty<String>()
      if (contentType.endsWith("web-text") || contentType.endsWith("web-text+proto")) {
        val base64Body = String(inputHttp.body)
        json = Optional.of(JSON.encode(GRPCMessage.decodeTextMessages(base64Body)))
      } else if (contentType.endsWith("web") || contentType.endsWith("web+proto")) {
        json = Optional.of(JSON.encode(GRPCMessage.decodeMessages(inputHttp.body)))
      }
      json.ifPresent { j -> inputHttp.setBody(j.toByteArray()) }
    }
    return inputHttp
  }

  @Throws(Exception::class)
  override fun encodeClientRequestHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (contentType.startsWith("application/grpc-web")) {
      val json: List<Map<String, Any?>> = JSON.decode(String(inputHttp.body))
      if (contentType.endsWith("web-text") || contentType.endsWith("web-text+proto")) {
        inputHttp.setBody(GRPCMessage.encodeTextMessages(json).toByteArray())
      } else if (contentType.endsWith("web") || contentType.endsWith("web+proto")) {
        inputHttp.setBody(GRPCMessage.encodeMessages(json))
      }
    }
    return inputHttp
  }
}
