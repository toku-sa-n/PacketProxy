/*
 * Copyright 2023 DeNA Co., Ltd.
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
package packetproxy.vulchecker.generator

import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import org.apache.commons.codec.binary.Base64
import packetproxy.common.JWTBase64

open class JWTAlgRS256 : JWTBase64 {
  private var privateKey: RSAPrivateKey

  @Throws(Exception::class)
  constructor(jwtString: String, pkcs8PrivateKey: ByteArray) : super(jwtString) {
    val keySpec = PKCS8EncodedKeySpec(pkcs8PrivateKey)
    val kf = KeyFactory.getInstance("RSA")
    this.privateKey = kf.generatePrivate(keySpec) as RSAPrivateKey
  }

  constructor(jwtString: String, privateKey: RSAPrivateKey) : super(jwtString) {
    this.privateKey = privateKey
  }

  @Throws(Exception::class)
  override fun createSignature(input: String): String {
    val signer = Signature.getInstance("SHA256withRSA")
    signer.initSign(this.privateKey)
    signer.update(input.toByteArray(StandardCharsets.UTF_8))
    val sign = signer.sign()
    return Base64.encodeBase64URLSafeString(sign)
  }
}
