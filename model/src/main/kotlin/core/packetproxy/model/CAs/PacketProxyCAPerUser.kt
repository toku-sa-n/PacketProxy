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
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.Calendar
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import packetproxy.common.Utils

class PacketProxyCAPerUser @Throws(Exception::class) constructor() : CA() {
  init {
    if (!File(ksPath).exists()) {
      generateKeyStore(ksPath)
    }
    super.load(ksPath)
  }

  override fun getName(): String = name

  override fun getUTF8Name(): String = desc

  override fun toString(): String = "PacketProxy per-user CA [name=$name, desc=$desc]"

  @Throws(Exception::class)
  override fun regenerateCA() {
    File(ksPath).delete()
    generateKeyStore(ksPath)
    super.load(ksPath)
  }

  @Throws(Exception::class)
  private fun generateKeyStore(ksPath: String) {
    var ks: KeyStore
    val CAKeyPair = super.genRSAKeyPair()

    // 各ユーザ用のキーストアを作るためのテンプレートを取得
    this.javaClass.getResourceAsStream("/certificates/user.ks").use { input ->
      ks = KeyStore.getInstance("JKS")
      ks.load(input, password)
    }

    var serialNumber = 0
    do {
      serialNumber = SecureRandom.getInstance("SHA1PRNG").nextInt()
    } while (serialNumber <= 0)

    val x500Name =
      String.format(
        "C=PacketProxy, ST=PacketProxy, L=PacketProxy, O=PacketProxy, OU=PacketProxy CA, CN=PacketProxy per-user CA (%x)",
        serialNumber,
      )
    val from = Date()
    val cal = Calendar.getInstance()
    cal.time = from
    cal.add(Calendar.YEAR, 30)
    val to = cal.time

    val caRootBuilder =
      X509v3CertificateBuilder(
        X500Name(x500Name),
        BigInteger.valueOf(serialNumber.toLong()),
        from,
        to,
        X500Name(x500Name),
        SubjectPublicKeyInfo.getInstance(CAKeyPair.public.encoded),
      )

    /* CA: X509 Extensionsの設定（CA:true, pathlen:0) */
    caRootBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(0))

    val sigAlgId = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")
    val digAlgId = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId)
    val signer =
      BcRSAContentSignerBuilder(sigAlgId, digAlgId)
        .build(PrivateKeyFactory.createKey(CAKeyPair.private.encoded))
    val signedRoot = caRootBuilder.build(signer)

    val certFactory = CertificateFactory.getInstance("X.509")
    registerCertificateAndPrivateKeyToKeyStore(
      certFactory.generateCertificate(ByteArrayInputStream(signedRoot.encoded)),
      CAKeyPair.private,
    )
  }

  @Throws(Exception::class)
  private fun registerCertificateAndPrivateKeyToKeyStore(
    certificate: Certificate,
    privateKey: PrivateKey,
  ) {
    // 新しいKeyStoreの生成
    val newks = KeyStore.getInstance("JKS")
    newks.load(null, password)

    // 証明書と秘密鍵の登録
    newks.setKeyEntry("root", privateKey, password, arrayOf(certificate))

    val newksfile = File(ksPath)
    newksfile.parentFile.mkdirs()
    newksfile.createNewFile()
    newksfile.setWritable(false, false)
    newksfile.setWritable(true)
    newksfile.setReadable(false, false)
    newksfile.setReadable(true)
    val fos = FileOutputStream(ksPath)
    newks.store(fos, password)
  }

  @Throws(Exception::class)
  fun importPEM(certificatePath: String, privateKeyPath: String) {
    val `is`: InputStream = Files.newInputStream(Paths.get(certificatePath))
    val cf = CertificateFactory.getInstance("X.509")
    val certificate = cf.generateCertificate(`is`)
    val b = Utils.readfile(privateKeyPath)
    val s = String(b).replace(Regex("-----.+?-----"), "").replace(Regex("\\r?\\n"), "")
    // PKCS#8のRSA鍵のみ対応
    val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(s))
    val kf = KeyFactory.getInstance("RSA")
    registerCertificateAndPrivateKeyToKeyStore(certificate, kf.generatePrivate(keySpec))
    super.load(ksPath)
  }

  @Throws(Exception::class)
  fun importDER(certificatePath: String, privateKeyPath: String) {
    val `is`: InputStream = Files.newInputStream(Paths.get(certificatePath))
    val cf = CertificateFactory.getInstance("X.509")
    val certificate = cf.generateCertificate(`is`)
    val b = Utils.readfile(privateKeyPath)
    // PKCS#8のRSA鍵のみ対応
    val keySpec = PKCS8EncodedKeySpec(b)
    val kf = KeyFactory.getInstance("RSA")
    registerCertificateAndPrivateKeyToKeyStore(certificate, kf.generatePrivate(keySpec))
    super.load(ksPath)
  }

  @Throws(Exception::class)
  fun importP12(p12Path: String, password: CharArray) {
    val inStream: InputStream = Files.newInputStream(Paths.get(p12Path))
    val ks = KeyStore.getInstance("PKCS12")
    ks.load(inStream, password)
    val alias = ks.aliases().nextElement()
    val certificate = ks.getCertificate(alias)
    val privateKey = ks.getKey(alias, password) as PrivateKey
    registerCertificateAndPrivateKeyToKeyStore(certificate, privateKey)
    super.load(ksPath)
  }

  override fun isExportable(): Boolean = true

  @Throws(Exception::class)
  override fun exportCertificatePEM(certificatePath: String) {
    val `is`: InputStream = FileInputStream(ksPath)
    val ks = KeyStore.getInstance("JKS")
    ks.load(`is`, password)
    val caRoot = ks.getCertificate("root")
    val s =
      "-----BEGIN CERTIFICATE-----\n" +
        Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(caRoot.encoded) +
        "\n-----END CERTIFICATE-----"
    val fos = FileOutputStream(certificatePath)
    fos.write(s.toByteArray())
    fos.close()
  }

  @Throws(Exception::class)
  override fun exportCertificateDER(certificatePath: String) {
    val `is`: InputStream = FileInputStream(ksPath)
    val ks = KeyStore.getInstance("JKS")
    ks.load(`is`, password)
    val caRoot = ks.getCertificate("root")
    val fos = FileOutputStream(certificatePath)
    fos.write(caRoot.encoded)
    fos.close()
  }

  @Throws(Exception::class)
  override fun exportPrivateKeyPEM(privateKeyPath: String) {
    val `is`: InputStream = FileInputStream(ksPath)
    val ks = KeyStore.getInstance("JKS")
    ks.load(`is`, password)
    val privateKey = ks.getKey("root", password) as PrivateKey
    val s =
      "-----BEGIN PRIVATE KEY-----\n" +
        Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(privateKey.encoded) +
        "\n-----END PRIVATE KEY-----"
    val fos = FileOutputStream(privateKeyPath)
    fos.write(s.toByteArray())
    fos.close()
  }

  @Throws(Exception::class)
  override fun exportPrivateKeyDER(privateKeyPath: String) {
    val `is`: InputStream = FileInputStream(ksPath)
    val ks = KeyStore.getInstance("JKS")
    ks.load(`is`, password)
    val privateKey = ks.getKey("root", password) as PrivateKey
    val fos = FileOutputStream(privateKeyPath)
    fos.write(privateKey.encoded)
    fos.close()
  }

  @Throws(Exception::class)
  override fun exportP12(p12Path: String, enteredPassword: CharArray) {
    val `is`: InputStream = FileInputStream(ksPath)
    val ks = KeyStore.getInstance("JKS")
    ks.load(`is`, password)
    val caRoot = ks.getCertificate("root")
    val privateKey = ks.getKey("root", password) as PrivateKey
    val newks = KeyStore.getInstance("PKCS12")
    newks.load(null, enteredPassword)
    newks.setKeyEntry("root", privateKey, enteredPassword, arrayOf(caRoot))
    val fos = FileOutputStream(p12Path)
    newks.store(fos, enteredPassword)
    fos.close()
  }

  companion object {
    private val name = "PacketProxy per-user CA"
    private val desc = "PacketProxy per-user CA"
    private val password = "testtest".toCharArray()
    private val ksPath =
      Paths.get(System.getProperty("user.home") + "/.packetproxy/certs/user.ks").toString()
  }
}
