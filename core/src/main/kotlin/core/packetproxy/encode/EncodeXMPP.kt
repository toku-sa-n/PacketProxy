/*
 * Copyright 2022 DeNA Co., Ltd.
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

import java.io.StringReader
import java.io.StringWriter
import java.nio.charset.StandardCharsets
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.OutputKeys
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import org.xml.sax.ErrorHandler
import org.xml.sax.InputSource
import org.xml.sax.SAXException
import org.xml.sax.SAXParseException

class EncodeXMPP(ALPN: String?) : Encoder(ALPN) {
  override fun getName(): String = "XMPP"

  override fun useNewConnectionForResend(): Boolean = false

  @Throws(Exception::class)
  override fun checkDelimiter(input_data: ByteArray): Int = input_data.size

  @Throws(Exception::class)
  override fun decodeClientRequest(input_data: ByteArray): ByteArray = xmlLint(input_data)

  @Throws(Exception::class)
  override fun encodeClientRequest(input_data: ByteArray): ByteArray = input_data

  @Throws(Exception::class)
  override fun decodeServerResponse(input_data: ByteArray): ByteArray = xmlLint(input_data)

  @Throws(Exception::class)
  override fun encodeServerResponse(input_data: ByteArray): ByteArray = input_data

  private inner class IgnoreErrorMsgHandler : ErrorHandler {
    @Throws(SAXException::class) override fun warning(ex: SAXParseException) {}

    @Throws(SAXException::class)
    override fun error(ex: SAXParseException) {
      throw ex
    }

    @Throws(SAXException::class)
    override fun fatalError(ex: SAXParseException) {
      throw ex
    }
  }

  private fun xmlLint(data: ByteArray): ByteArray {
    try {
      val dbf = createSecureDocumentBuilderFactory()
      val db = dbf.newDocumentBuilder()
      db.setErrorHandler(IgnoreErrorMsgHandler())
      val `is` = InputSource(StringReader(String(data, StandardCharsets.UTF_8)))
      val doc = db.parse(`is`)
      val transformer = TransformerFactory.newInstance().newTransformer()
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
      transformer.setOutputProperty(OutputKeys.INDENT, "yes")
      transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2")
      val result = StreamResult(StringWriter())
      val source = DOMSource(doc)
      transformer.transform(source, result)
      return result.writer.toString().toByteArray(StandardCharsets.UTF_8)
    } catch (e: Exception) {
      return data
    }
  }

  companion object {
    /** Factory with XXE protections enabled — used by production decode and tests. */
    fun createSecureDocumentBuilderFactory(): DocumentBuilderFactory {
      val dbf = DocumentBuilderFactory.newInstance()
      dbf.isValidating = false
      dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
      dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
      dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
      dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
      dbf.isXIncludeAware = false
      dbf.isExpandEntityReferences = false
      return dbf
    }
  }
}
