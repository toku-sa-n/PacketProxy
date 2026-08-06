package packetproxy.encode

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class EncodeXMPPFactoryTest {
  @Test
  fun createSecureDocumentBuilderFactoryDisablesXxeFeatures() {
    val dbf = EncodeXMPP.createSecureDocumentBuilderFactory()
    assertFalse(dbf.isExpandEntityReferences)
    assertFalse(dbf.isXIncludeAware)
    // Features that should reject external entity resolution
    assertTrue(dbf.getFeature("http://apache.org/xml/features/disallow-doctype-decl"))
    assertFalse(dbf.getFeature("http://xml.org/sax/features/external-general-entities"))
    assertFalse(dbf.getFeature("http://xml.org/sax/features/external-parameter-entities"))
  }
}
