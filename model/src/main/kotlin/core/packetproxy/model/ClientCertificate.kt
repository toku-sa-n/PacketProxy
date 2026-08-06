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
package packetproxy.model

import com.j256.ormlite.field.DatabaseField
import com.j256.ormlite.table.DatabaseTable
import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Objects
import java.util.regex.Pattern
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory

/** Certificate Model for Client Certificate Authentication */
@DatabaseTable(tableName = "clientCertificates")
class ClientCertificate {
  @field:DatabaseField(generatedId = true) private var id = 0

  @field:DatabaseField private var enabled: Boolean? = null

  @field:DatabaseField(uniqueCombo = true) private var type: Type? = null

  @field:DatabaseField(uniqueCombo = true) private var serverId = 0

  @field:DatabaseField private var subject: String? = null

  @field:DatabaseField private var issuer: String? = null

  @field:DatabaseField(uniqueCombo = true) private var path: String? = null

  @field:DatabaseField private var storePassword: String? = null

  @field:DatabaseField private var keyPassword: String? = null

  constructor()

  constructor(
    type: Type,
    server: Server,
    subject: String,
    issuer: String,
    path: String,
    storePassword: String,
    keyPassword: String,
  ) {
    this.enabled = false
    this.type = type
    this.serverId = server.getId()
    this.subject = subject
    this.issuer = issuer
    this.path = path
    this.storePassword = storePassword
    this.keyPassword = keyPassword
  }

  /**
   * Load for getting KeyManager[] from this model
   *
   * @return KeyManager for Client Certificate
   * @throws Exception:
   *     - IOException - KeyStoreException - CertificateException - NoSuchAlgorithmException -
   *       UnrecoverableKeyException
   */
  @Throws(Exception::class)
  fun load(): Array<KeyManager> {
    // Load KeyStore
    val fis = FileInputStream(path)
    val keyStore = KeyStore.getInstance(type!!.getText())
    keyStore.load(fis, storePassword!!.toCharArray())
    fis.close()

    val kmf = KeyManagerFactory.getInstance("SunX509")
    kmf.init(keyStore, keyPassword!!.toCharArray())

    return kmf.keyManagers
  }

  enum class Type(private val text: String) {
    P12("PKCS12"),
    JKS("JKS");

    // BKS("BKS"),

    fun getText(): String = this.text

    companion object {
      @JvmStatic
      fun getTypeFromText(t: String): Type? {
        for (type in Type.values()) {
          if (Objects.equals(type.getText(), t)) {
            return type
          }
        }
        return null
      }
    }
  }

  // Getter / Setter
  fun getId(): Int = id

  fun getEnabled(): Boolean? = enabled

  fun setEnabled(enabled: Boolean) {
    this.enabled = enabled
  }

  fun getServerId(): Int = this.serverId

  fun setServerId(serverId: Int) {
    this.serverId = serverId
  }

  fun getType(): Type? = this.type

  fun setType(type: Type) {
    this.type = type
  }

  fun getSubject(): String? = this.subject

  fun setSubject(subject: String) {
    this.subject = subject
  }

  fun getIssuer(): String? = this.issuer

  fun setIssuer(issuer: String) {
    this.issuer = issuer
  }

  fun getPath(): String? = path

  fun setPath(path: String) {
    this.path = path
  }

  fun getStorePassword(): String? = storePassword

  fun setStorePassword(storePassword: String) {
    this.storePassword = storePassword
  }

  fun getKeyPassword(): String? = keyPassword

  fun setKeyPassword(keyPassword: String) {
    this.keyPassword = keyPassword
  }

  fun isEnabled(): Boolean = this.enabled ?: false

  fun setEnabled() {
    this.enabled = true
  }

  fun setDisabled() {
    this.enabled = false
  }

  @Throws(Exception::class)
  fun getServer(database: Database): Server? =
    database.createTable(Server::class.java).queryForId(this.serverId)

  @Throws(Exception::class)
  fun getServerName(database: Database): String {
    val server = getServer(database)
    return if (server != null) server.toString() else ""
  }

  override fun hashCode(): Int = this.getId()

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is ClientCertificate) return false
    return this.getId() == other.getId()
  }

  companion object {
    /**
     * Convert from Client Certificate file into this model
     *
     * @param type: Certificate Type (e.g. PKCS#12, JKS)
     * @param server: Applied Server
     * @param path: Certificate Path on File System
     * @param storePassword: Password for Certificate
     * @param keyPassword: Password for Private Key
     * @return Model for Client Certificate
     * @throws Exception:
     *     - IOException - FileNotFoundException - KeyStoreException - NoSuchAlgorithmException -
     *       CertificateException
     */
    @JvmStatic
    @Throws(Exception::class)
    fun convert(
      type: Type,
      server: Server,
      path: String,
      storePassword: CharArray,
      keyPassword: CharArray,
    ): ClientCertificate {
      // Load KeyStore
      val fis = FileInputStream(path)
      val ks = KeyStore.getInstance(type.getText())
      ks.load(fis, storePassword)
      fis.close()

      // Get an alias of FIRST ONLY!!!
      val alias = ks.aliases().nextElement()

      // Extract CommonName and Issuer
      val crt = ks.getCertificate(alias) as X509Certificate
      val subject = getCommonName(crt.subjectDN.name)
      val issuer = crt.issuerDN.name

      return ClientCertificate(
        type,
        server,
        subject,
        issuer,
        path,
        String(storePassword),
        String(keyPassword),
      )
    }

    /**
     * Get CommonName from SubjectDN. If regex capture is failed, return inputted SubjectDN.
     *
     * @param subject: SubjectDN
     * @return cn or subject
     */
    private fun getCommonName(subject: String): String {
      val pattern = Pattern.compile("CN=(.*?),")
      val matcher = pattern.matcher(subject)

      if (matcher.find() && matcher.group(1) != "") return matcher.group(1)
      return subject
    }
  }
}
