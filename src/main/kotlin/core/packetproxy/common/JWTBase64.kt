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

import org.apache.commons.codec.binary.Base64

open class JWTBase64 : JWT {
  constructor(jwt: JWT) : super(jwt)

  constructor(jwtString: String) {
    val jwtPart = jwtString.split(".", limit = 3)
    header = String(Base64.decodeBase64(jwtPart[0]))
    payload = String(Base64.decodeBase64(jwtPart[1]))
  }

  override fun toJwtString(): String {
    val builder = StringBuilder()
    builder.append(createHeader(header))
    builder.append(".")
    builder.append(createPayload(payload))
    val headerPayload = builder.toString()
    val signature = createSignature(headerPayload)
    builder.append(".")
    if (signature.isNotEmpty()) builder.append(signature)
    return builder.toString()
  }

  @Throws(Exception::class) open override fun createSignature(input: String): String = "NotDefined"

  open override fun createHeader(input: String?): String =
    Base64.encodeBase64URLSafeString((input ?: "").toByteArray())

  open override fun createPayload(input: String?): String =
    Base64.encodeBase64URLSafeString((input ?: "").toByteArray())
}
