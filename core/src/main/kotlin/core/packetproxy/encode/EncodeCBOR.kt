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

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import packetproxy.http.Http
import packetproxy.util.errWithStackTrace

class EncodeCBOR @Throws(Exception::class) constructor(ALPN: String?) : EncodeHTTPBase(ALPN) {
  private var cborMapper: ObjectMapper
  private var jsonMapper: ObjectMapper

  init {
    val f = CBORFactory()
    cborMapper = ObjectMapper(f)
    jsonMapper = ObjectMapper()
  }

  override fun getName(): String = "CBOR over HTTP"

  @Throws(Exception::class)
  override fun decodeClientRequestHttp(inputHttp: Http): Http {
    inputHttp.setBody(cborToJson(inputHttp.body))
    return inputHttp
  }

  @Throws(Exception::class)
  override fun encodeClientRequestHttp(inputHttp: Http): Http {
    inputHttp.setBody(jsonToCbor(inputHttp.body))
    return inputHttp
  }

  @Throws(Exception::class)
  override fun decodeServerResponseHttp(inputHttp: Http): Http {
    inputHttp.setBody(cborToJson(inputHttp.body))
    return inputHttp
  }

  @Throws(Exception::class)
  override fun encodeServerResponseHttp(inputHttp: Http): Http {
    inputHttp.setBody(jsonToCbor(inputHttp.body))
    return inputHttp
  }

  private fun cborToJson(src: ByteArray): ByteArray = ObjToAltObj(src, cborMapper, jsonMapper)

  private fun jsonToCbor(src: ByteArray): ByteArray = ObjToAltObj(src, jsonMapper, cborMapper)

  private fun ObjToAltObj(
    src: ByteArray,
    srcObjMapper: ObjectMapper,
    dstObjMapper: ObjectMapper,
  ): ByteArray {
    try {
      val objMap: Map<String, Any> =
        srcObjMapper.readValue(src, object : TypeReference<Map<String, Any>>() {})
      return dstObjMapper.writeValueAsBytes(objMap)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    return ByteArray(0)
  }
}
