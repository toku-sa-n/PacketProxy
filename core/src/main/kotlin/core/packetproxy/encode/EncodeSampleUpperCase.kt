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

class EncodeSampleUpperCase @Throws(Exception::class) constructor(ALPN: String?) : Encoder(ALPN) {
  override fun getName(): String = "Sample UpperCase"

  /* 1つのリクエスト/レスポンスのサイズで区切ってください */
  @Throws(Exception::class)
  override fun checkDelimiter(input_data: ByteArray): Int = input_data.size

  @Throws(Exception::class)
  override fun decodeServerResponse(input_data: ByteArray): ByteArray =
    String(input_data).uppercase().toByteArray()

  @Throws(Exception::class)
  override fun encodeServerResponse(input_data: ByteArray): ByteArray =
    String(input_data).lowercase().toByteArray()

  @Throws(Exception::class)
  override fun decodeClientRequest(input_data: ByteArray): ByteArray =
    String(input_data).uppercase().toByteArray()

  @Throws(Exception::class)
  override fun encodeClientRequest(input_data: ByteArray): ByteArray =
    String(input_data).lowercase().toByteArray()
}
