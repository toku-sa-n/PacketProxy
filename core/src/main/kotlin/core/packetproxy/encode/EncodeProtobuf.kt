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

import packetproxy.common.Protobuf3
import packetproxy.http.Http

class EncodeProtobuf @Throws(Exception::class) constructor(ALPN: String?) : EncodeHTTPBase(ALPN) {
  override fun getName(): String = "Protocol Buffer over HTTP"

  @Throws(Exception::class)
  override fun decodeClientRequestHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (contentType.contains("protobuf")) {
      return decodeProtobuf3(inputHttp)
    }
    return inputHttp
  }

  @Throws(Exception::class)
  override fun encodeClientRequestHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (contentType.contains("protobuf")) {
      return encodeProtobuf3(inputHttp)
    }
    return inputHttp
  }

  @Throws(Exception::class)
  override fun decodeServerResponseHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (contentType.contains("protobuf")) {
      return decodeProtobuf3(inputHttp)
    }
    return inputHttp
  }

  @Throws(Exception::class)
  override fun encodeServerResponseHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (contentType.contains("protobuf")) {
      return encodeProtobuf3(inputHttp)
    }
    return inputHttp
  }

  @Throws(Exception::class)
  private fun decodeProtobuf3(inputHttp: Http): Http {
    val body = inputHttp.body
    val decoded = Protobuf3.decode(body)
    inputHttp.setBody(decoded.toByteArray())
    return inputHttp
  }

  @Throws(Exception::class)
  private fun encodeProtobuf3(inputHttp: Http): Http {
    val body = inputHttp.body
    val encoded = Protobuf3.encode(String(body))
    inputHttp.setBody(encoded)
    return inputHttp
  }
}
