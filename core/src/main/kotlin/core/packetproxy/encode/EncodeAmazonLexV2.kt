/*
 * Copyright 2025 DeNA Co., Ltd.
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

import com.google.gson.GsonBuilder
import packetproxy.common.AmazonLexV2
import packetproxy.http.Http
import packetproxy.util.Logging.log

class EncodeAmazonLexV2 @Throws(Exception::class) constructor(ALPN: String?) :
  EncodeHTTPBase(ALPN) {
  override fun getName(): String = "Amazon LexV2 (Event Streaming)"

  @Throws(Exception::class) override fun decodeClientRequestHttp(inputHttp: Http): Http = inputHttp

  @Throws(Exception::class) override fun encodeClientRequestHttp(inputHttp: Http): Http = inputHttp

  @Throws(Exception::class)
  override fun decodeServerResponseHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (!contentType.startsWith("application/vnd.amazon.eventstream")) {
      log(
        "[EncodeAmazonLexV2] decodeServerResponseHttp: Content-type is not specified or other content-type detected: %s",
        contentType,
      )
      return inputHttp
    }
    val body = inputHttp.body

    val event = AmazonLexV2.fromBytes(body)

    val gson = GsonBuilder().create()
    val json = gson.toJson(event)

    inputHttp.setBody(json.toByteArray(Charsets.UTF_8))
    return inputHttp
  }

  @Throws(Exception::class)
  override fun encodeServerResponseHttp(inputHttp: Http): Http {
    val contentType = inputHttp.getFirstHeader("Content-Type")
    if (!contentType.startsWith("application/vnd.amazon.eventstream")) {
      log(
        "[EncodeAmazonLexV2] encodeServerResponseHttp: Content-type is not specified or other content-type detected: %s",
        contentType,
      )
      return inputHttp
    }

    val body = inputHttp.body
    if (body.isEmpty()) {
      log("[EncodeAmazonLexV2] Warning: Empty body detected, skipping encoding.")
      return inputHttp
    }

    val gson = GsonBuilder().create()

    val lex = gson.fromJson(String(body, Charsets.UTF_8), AmazonLexV2::class.java)

    if (lex == null) {
      log(
        "[EncodeAmazonLexV2] Warning: Invalid Amazon Lex V2 Event Stream detected, skipping encoding."
      )
      return inputHttp
    }

    val encoded = AmazonLexV2.toBytes(lex)

    inputHttp.setBody(encoded)

    return inputHttp
  }
}
