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
package packetproxy.model.CAs

import java.io.ByteArrayInputStream
import java.io.FileInputStream
import java.io.InputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.util.Calendar
import java.util.Date
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder

abstract class CA {
  private var keyPair: KeyPair? = null
  private var keyStoreCAPath: String? = null
  private var keyStoreCA: KeyStore? = null
  private var keyStoreCAPrivateKey: PrivateKey? = null

  private var caRootHolder: X509CertificateHolder? = null
  private var templateIssuer: X500Name? = null
  private var templatePubKey: SubjectPublicKeyInfo? = null

  private val aliasRoot = "root"
  private val aliasServer = "newalias"
  private val password = "testtest".toCharArray()
  private val secureRandom = java.security.SecureRandom()

  protected constructor()

  @Throws(Exception::class)
  protected fun load(keyStoreCAPath: String) {
    this.keyPair = genRSAKeyPair()
    this.keyStoreCAPath = keyStoreCAPath
    FileInputStream(this.keyStoreCAPath!!).use { input -> initKeyStoreCA(input) }
  }

  @Throws(Exception::class)
  protected fun loadFromResource(keyStoreCAPath: String) {
    this.keyPair = genRSAKeyPair()
    this.keyStoreCAPath = keyStoreCAPath
    this.javaClass.getResourceAsStream(this.keyStoreCAPath!!).use { input ->
      initKeyStoreCA(input!!)
    }
  }

  @Throws(Exception::class)
  protected fun genRSAKeyPair(): KeyPair {
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    return kpg.genKeyPair()
  }

  @Throws(Exception::class)
  private fun initKeyStoreCA(input: InputStream) {
    this.keyStoreCA = KeyStore.getInstance("JKS")
    this.keyStoreCA!!.load(input, password)

    this.keyStoreCAPrivateKey = keyStoreCA!!.getKey(aliasRoot, password) as PrivateKey

    /* RootのSubject(Issuer)の取り出し */
    val caRootCert = keyStoreCA!!.getCertificate(aliasRoot)
    caRootHolder = X509CertificateHolder(caRootCert.encoded)

    /* Templateの設定 (validity is computed at issue time) */
    templateIssuer = caRootHolder!!.subject
    templatePubKey = SubjectPublicKeyInfo.getInstance(keyPair!!.public.encoded)
  }

  @Throws(Exception::class)
  open fun createKeyStore(commonName: String, domainNames: Array<String>): KeyStore {
    /* シリアルナンバーの設定 — positive BigInteger from hash or 128-bit SecureRandom */
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(commonName.toByteArray(Charsets.UTF_8))
    var templateSerial = BigInteger(1, hash.copyOf(16))
    if (templateSerial.signum() == 0) {
      val randomBytes = ByteArray(16)
      secureRandom.nextBytes(randomBytes)
      templateSerial = BigInteger(1, randomBytes)
    }

    /* 有効期限は発行時に計算 */
    val from = Date()
    val cal = Calendar.getInstance()
    cal.time = from
    cal.add(Calendar.YEAR, 1)
    val to = cal.time

    /* Subjectの設定 */
    val templateSubject = X500Name(createSubject(commonName))

    /* Builderの生成 */
    val serverBuilder =
      X509v3CertificateBuilder(
        templateIssuer,
        templateSerial,
        from,
        to,
        templateSubject,
        templatePubKey,
      )

    /* SANの設定 */
    val sans = ArrayList<ASN1Encodable>()
    sans.add(GeneralName(GeneralName.dNSName, createCNforSAN(commonName)))
    /*
     Fix: SubjectCN = SANに変更
     Reason: SANに全てのサーバが入っていると、HTTP2通信のとき、1つのHTTP2コネクション内に複数サーバ宛のストリームが含まれてしまうケースがあるため
    */
    // for (String domainName : domainNames) {
    // sans.add(new GeneralName(GeneralName.dNSName, domainName));
    // }
    val subjectAlternativeNames = DERSequence(sans.toTypedArray())
    serverBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames)

    // 署名
    val serverHolder = serverBuilder.build(createSigner())

    /* 新しいKeyStoreを作成 */
    val certFactory = CertificateFactory.getInstance("X.509")
    val ks = KeyStore.getInstance("JKS")
    ks.load(null, password)
    ks.setKeyEntry(
      aliasServer,
      keyPair!!.private,
      password,
      arrayOf(
        certFactory.generateCertificate(ByteArrayInputStream(serverHolder.encoded)),
        certFactory.generateCertificate(ByteArrayInputStream(caRootHolder!!.encoded)),
      ),
    )

    return ks
  }

  protected open fun createSubject(commonName: String): String =
    String.format(
      "C=PacketProxy, ST=PacketProxy, L=PacketProxy, O=PacketProxy, OU=PacketProxy, CN=%s",
      escapeX500Value(commonName),
    )

  protected open fun createCNforSAN(commonName: String): String = commonName

  /** Escape special characters for RFC 4514 / X500Name attribute values. */
  protected fun escapeX500Value(value: String): String {
    if (value.isEmpty()) return value
    val sb = StringBuilder(value.length + 8)
    value.forEachIndexed { index, c ->
      when {
        c == '\\' ||
          c == ',' ||
          c == '+' ||
          c == '"' ||
          c == '<' ||
          c == '>' ||
          c == ';' ||
          c == '=' ||
          c == '#' && index == 0 ||
          c == ' ' && (index == 0 || index == value.lastIndex) -> {
          sb.append('\\').append(c)
        }
        c.code < 0x20 -> {
          sb.append('\\').append("%02X".format(c.code))
        }
        else -> sb.append(c)
      }
    }
    return sb.toString()
  }

  @Throws(Exception::class)
  protected open fun createSigner(): ContentSigner {
    val sigAlgId = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")
    val digAlgId = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId)
    return BcRSAContentSignerBuilder(sigAlgId, digAlgId)
      .build(PrivateKeyFactory.createKey(keyStoreCAPrivateKey!!.encoded))
  }

  open fun getName(): String = "Unknown CA"

  open fun getUTF8Name(): String = "Unknown CA"

  override fun toString(): String = "Unknown CA"

  @Throws(Exception::class)
  open fun regenerateCA() {
    throw RuntimeException("Not Implemented.")
  }

  // export可能なCAのとき、継承してtrueを返すこと
  open fun isExportable(): Boolean = false

  // export可能なCAのとき、継承して実装すること
  @Throws(Exception::class)
  open fun exportCertificatePEM(certificatePath: String) {
    throw RuntimeException("Not Implemented.")
  }

  // export可能なCAのとき、継承して実装すること
  @Throws(Exception::class)
  open fun exportCertificateDER(certificatePath: String) {
    throw RuntimeException("Not Implemented.")
  }

  // export可能なCAのとき、継承して実装すること
  @Throws(Exception::class)
  open fun exportPrivateKeyPEM(privateKeyPath: String) {
    throw RuntimeException("Not Implemented.")
  }

  // export可能なCAのとき、継承して実装すること
  @Throws(Exception::class)
  open fun exportPrivateKeyDER(privateKeyPath: String) {
    throw RuntimeException("Not Implemented.")
  }

  // export可能なCAのとき、継承して実装すること
  @Throws(Exception::class)
  open fun exportP12(p12Path: String, enteredPassword: CharArray) {
    throw RuntimeException("Not Implemented.")
  }
}
