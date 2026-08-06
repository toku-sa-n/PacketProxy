// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class SVCBRecordTest {
  @Test
  fun createParams() {
    val mandatoryList = listOf(SVCBRecord.ALPN, SVCBRecord.IPV4HINT)
    val mandatory = SVCBBase.ParameterMandatory(mandatoryList)
    assertEquals(SVCBRecord.MANDATORY, mandatory.key)
    assertEquals(mandatoryList, mandatory.values)
    val alpnList = listOf("h2", "h3")
    val alpn = SVCBBase.ParameterAlpn(alpnList)
    assertEquals(SVCBRecord.ALPN, alpn.key)
    assertEquals(alpnList, alpn.values)
    val port = SVCBBase.ParameterPort(8443)
    assertEquals(SVCBRecord.PORT, port.key)
    assertEquals(8443, port.port)
    val ipv4List = listOf(InetAddress.getByName("1.2.3.4") as Inet4Address)
    val ipv4hint = SVCBBase.ParameterIpv4Hint(ipv4List)
    assertEquals(SVCBRecord.IPV4HINT, ipv4hint.key)
    assertEquals(ipv4List, ipv4hint.addresses)
    val data = byteArrayOf('a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte())
    val echconfig = SVCBBase.ParameterEch(data)
    assertEquals(SVCBRecord.ECH, echconfig.key)
    assertEquals(data, echconfig.data)
    val ipv6List = listOf(InetAddress.getByName("2001::1") as Inet6Address)
    val ipv6hint = SVCBBase.ParameterIpv6Hint(ipv6List)
    assertEquals(SVCBRecord.IPV6HINT, ipv6hint.key)
    assertEquals(ipv6List, ipv6hint.addresses)
    val value = byteArrayOf(0, 1, 2, 3)
    val unknown = SVCBBase.ParameterUnknown(33, value)
    assertEquals(33, unknown.key)
    assertEquals(value, unknown.value)
  }

  @Test
  fun createRecord() {
    val label = Name.fromString("test.com.")
    val svcPriority = 5
    val svcDomain = Name.fromString("svc.test.com.")
    val mandatory = SVCBBase.ParameterMandatory()
    mandatory.fromString("alpn")
    val alpn = SVCBBase.ParameterAlpn()
    alpn.fromString("h1,h2")
    val ipv4 = SVCBBase.ParameterIpv4Hint()
    ipv4.fromString("1.2.3.4,5.6.7.8")
    val params = listOf(mandatory, ipv4, alpn)
    val record = SVCBRecord(label, DClass.IN, 300, svcPriority, svcDomain, params)
    assertEquals(Type.SVCB, record.type)
    assertEquals(label, record.name)
    assertEquals(svcPriority, record.svcPriority)
    assertEquals(svcDomain, record.targetName)
    assertEquals(
      listOf(SVCBRecord.MANDATORY, SVCBRecord.ALPN, SVCBRecord.IPV4HINT).toString(),
      record.svcParamKeys.toString(),
    )
    assertEquals("alpn", record.getSvcParamValue(SVCBRecord.MANDATORY).toString())
    assertEquals("h1,h2", record.getSvcParamValue(SVCBRecord.ALPN).toString())
    assertEquals("h1,h2", record.getSvcParamValue(SVCBRecord.ALPN).toString())
    assertNull(record.getSvcParamValue(1234))
    Options.unset("BINDTTL")
    Options.unset("noPrintIN")
    assertEquals(
      "test.com.\t\t300\tIN\tSVCB\t5 svc.test.com. mandatory=alpn alpn=h1,h2 ipv4hint=1.2.3.4,5.6.7.8",
      record.toString(),
    )
  }

  @Test
  fun createRecordDuplicateParam() {
    val label = Name.fromString("test.com.")
    val svcDomain = Name.fromString("svc.test.com.")
    val alpn = SVCBBase.ParameterAlpn()
    alpn.fromString("h1,h2")
    val ipv4 = SVCBBase.ParameterIpv4Hint()
    ipv4.fromString("1.2.3.4,5.6.7.8")
    val params = listOf(alpn, ipv4, alpn)
    assertThrows<IllegalArgumentException> {
      SVCBRecord(label, DClass.IN, 300, 5, svcDomain, params)
    }
  }

  @Test
  fun aliasMode() {
    val str = "0 a.b.c."
    val bytes = stringToWire(str)
    val expected =
      byteArrayOf(0, 0, 1, 'a'.code.toByte(), 1, 'b'.code.toByte(), 1, 'c'.code.toByte(), 0)
    assertArrayEquals(expected, bytes)
    assertEquals(str, wireToString(bytes))
  }

  @Test
  fun serviceModePort() {
    val str = "1 . port=8443"
    val bytes = stringToWire(str)
    val expected = byteArrayOf(0, 1, 0, 0, 3, 0, 2, 0x20, 0xFB.toByte())
    assertArrayEquals(expected, bytes)
    assertEquals(str, wireToString(bytes))
  }

  @Test fun serviceModeAlpn() = assertRoundTrip("1 . alpn=h3")

  @Test fun serviceModeNoDefaultAlpn() = assertRoundTrip("1 . no-default-alpn")

  @Test fun serviceModeMultiKey() = assertRoundTrip("1 . alpn=h3 no-default-alpn")

  @Test fun serviceModeIntKey() = assertEquals("1 . alpn=h3", stringToWireToString("1 . 1=h3"))

  @Test
  fun serviceModeMultiValue() {
    val str = "1 . alpn=h2,h3"
    val bytes = stringToWire(str)
    val expected =
      byteArrayOf(
        0,
        1,
        0,
        0,
        1,
        0,
        6,
        2,
        'h'.code.toByte(),
        '2'.code.toByte(),
        2,
        'h'.code.toByte(),
        '3'.code.toByte(),
      )
    assertArrayEquals(expected, bytes)
    assertEquals(str, wireToString(bytes))
  }

  @Test
  fun serviceModeQuotedValue() =
    assertEquals("1 . alpn=h2,h3", stringToWireToString("1 . alpn=\"h2,h3\""))

  @Test
  fun serviceModeQuotedEscapedValue() =
    assertEquals("1 . alpn=h2\\,h3,h4", stringToWireToString("1 . alpn=\"h2\\,h3,h4\""))

  @Test
  fun serviceModeMandatoryAndOutOfOrder() =
    assertEquals(
      "1 . mandatory=alpn alpn=h3 no-default-alpn",
      stringToWireToString("1 . alpn=h3 no-default-alpn mandatory=alpn"),
    )

  @Test
  fun serviceModeEscapedDomain() = assertRoundTrip("1 dotty\\.lotty.example.com. no-default-alpn")

  @Test
  fun serviceModeEchConfig() =
    assertEquals("1 h3pool. ech=1234", stringToWireToString("1 h3pool. echconfig=1234"))

  @Test
  fun serviceModeEchConfigMulti() =
    assertEquals(
      "1 h3pool. alpn=h2,h3 ech=1234",
      stringToWireToString("1 h3pool. alpn=h2,h3 echconfig=1234"),
    )

  @Test
  fun serviceModeEchConfigOutOfOrder() =
    assertEquals(
      "1 h3pool. alpn=h2,h3 ech=1234",
      stringToWireToString("1 h3pool. echconfig=1234 alpn=h2,h3"),
    )

  @Test
  fun serviceModeEchConfigQuoted() =
    assertEquals(
      "1 h3pool. alpn=h2,h3 ech=1234",
      stringToWireToString("1 h3pool. alpn=h2,h3 echconfig=\"1234\""),
    )

  @Test fun serviceModeIpv4Hint() = assertRoundTrip("3 . ipv4hint=4.5.6.7")

  @Test
  fun serviceModeIpv4HintList() {
    val str = "5 . ipv4hint=4.5.6.7,8.9.1.2"
    val bytes = stringToWire(str)
    val expected = byteArrayOf(0, 5, 0, 0, 4, 0, 8, 4, 5, 6, 7, 8, 9, 1, 2)
    assertArrayEquals(expected, bytes)
    assertEquals(str, wireToString(bytes))
  }

  @Test
  fun serviceModeIpv4HintQuoted() =
    assertEquals(
      "5 . ipv4hint=4.5.6.7,8.9.1.2",
      stringToWireToString("5 . ipv4hint=\"4.5.6.7,8.9.1.2\""),
    )

  @Test fun serviceModeIpv4HintMultiKey() = assertRoundTrip("7 . alpn=h2 ipv4hint=4.5.6.7")

  @Test
  fun serviceModeIpv6Hint() =
    assertEquals(
      "9 . ipv6hint=2001:2002:0:0:0:0:0:1",
      stringToWireToString("9 . ipv6hint=2001:2002::1"),
    )

  @Test
  fun serviceModeIpv6HintMulti() =
    assertEquals(
      "2 . alpn=h2 ipv6hint=2001:2002:0:0:0:0:0:1,2001:2002:0:0:0:0:0:2",
      stringToWireToString("2 . alpn=h2 ipv6hint=2001:2002::1,2001:2002::2"),
    )

  @Test fun serviceModeUnknownKey() = assertRoundTrip("6 . key12345=abcdefg\\012")

  @Test
  fun serviceModeUnknownKeyBytes() {
    val str = "8 . key23456=\\000\\001\\002\\003"
    val bytes = stringToWire(str)
    val expected = byteArrayOf(0, 8, 0, 0x5B, 0xA0.toByte(), 0, 4, 0, 1, 2, 3)
    assertArrayEquals(expected, bytes)
    assertEquals(str, wireToString(bytes))
  }

  @Test
  fun serviceModeUnknownKeyEscapedChars() =
    assertEquals("1 . key29=abc", stringToWireToString("1 . key29=a\\b\\c"))

  @Test fun serviceModeUnknownKeyEscapedSlash() = assertRoundTrip("65535 . key29=a\\\\b\\\\c")

  @Test fun serviceModeUnknownHighKey() = assertRoundTrip("65535 . key65535=abcdefg")

  @Test fun serviceModeUnknownKeyNoValue() = assertRoundTrip("65535 . key65535")

  @Test fun invalidText() = assertTextParseFails("these are all garbage strings that should fail")

  @Test
  fun extraQuotesInParamValues() = assertTextParseFails("5 . ipv4hint=\"4.5.6.7\",\"8.9.1.2\"")

  @Test fun serviceModeWithoutParameters() = assertRoundTrip("1 aliasmode.example.com.")

  @Test fun aliasModeWithParameters() = assertTextParseFails("0 . alpn=h3")

  @Test fun zeroLengthMandatory() = assertTextParseFails("1 . mandatory")

  @Test fun zeroLengthAlpnValue() = assertTextParseFails("1 . alpn")

  @Test fun zeroLengthPortValue() = assertTextParseFails("1 . port")

  @Test fun zeroLengthIpv4Hint() = assertTextParseFails("1 . ipv4hint")

  @Test fun zeroLengthEchConfig() = assertTextParseFails("1 . echconfig")

  @Test fun zeroLengthIpv6Hint() = assertTextParseFails("1 . ipv6hint")

  @Test fun emptyKey() = assertTextParseFails("1 . =1234")

  @Test fun emptyValue() = assertTextParseFails("1 . alpn=")

  @Test fun emptyKeyAndValue() = assertTextParseFails("1 . =")

  @Test fun unknownKey() = assertTextParseFails("1 . sport=8443")

  @Test fun mandatoryListWithSelf() = assertTextParseFails("1 . mandatory=alpn,mandatory alpn=h1")

  @Test
  fun mandatoryListWithDuplicate() =
    assertTextParseFails("1 . mandatory=alpn,ipv4hint,alpn alpn=h1 ipv4hint=1.2.3.4")

  @Test
  fun mandatoryListWithMissingParam() = assertTextParseFails("1 . mandatory=alpn,ipv4hint alpn=h1")

  @Test
  fun portValueTooLarge() {
    assertThrows<IllegalArgumentException> { stringToWire("1 . port=84438") }
  }

  @Test fun noDefaultAlpnWithValue() = assertTextParseFails("1 . no-default-alpn=true")

  @Test fun emptyString() = assertTextParseFails("")

  @Test fun noParamValues() = assertRoundTrip("1 .")

  @Test fun svcPriorityTooHigh() = assertTextParseFails("65536 . port=443")

  @Test fun invalidPortKey() = assertTextParseFails("1 . port<5")

  @Test fun invalidSvcDomain() = assertTextParseFails("1 fred..harvey port=80")

  @Test fun duplicateParamKey() = assertTextParseFails("1 . alpn=h2 alpn=h3")

  @Test fun invalidIpv4Hint() = assertTextParseFails("1 . ipv4hint=2001::1")

  @Test fun invalidIpv6Hint() = assertTextParseFails("1 . ipv6hint=1.2.3.4")

  @Test fun negativeSvcPriority() = assertTextParseFails("-1 . port=80")

  @Test fun svcParamUnknownKeyTooHigh() = assertTextParseFails("65535 . key65536=abcdefg")

  @Test fun invalidSvcParamKey() = assertTextParseFails("65535 . keyBlooie=abcdefg")

  @Test fun wireFormatTooShort() = assertWireParseFails(byteArrayOf(0, 1, 0, 0, 1, 0, 10))

  @Test fun wireFormatTooLong() = assertWireParseFails(byteArrayOf(0, 0, 0, 1))

  @Test
  fun wireFormatMandatoryTooLong() =
    assertWireParseFails(byteArrayOf(0, 1, 0, 0, 0, 0, 3, 0, 1, 55))

  @Test
  fun wireFormatAlpnTooShort() = assertWireParseFails(byteArrayOf(0, 1, 0, 0, 1, 0, 3, 10, 1, 55))

  @Test
  fun wireFormatNoDefaultAlpnTooLong() = assertWireParseFails(byteArrayOf(0, 1, 0, 0, 2, 0, 1, 0))

  @Test
  fun wireFormatPortTooLong() = assertWireParseFails(byteArrayOf(0, 1, 0, 0, 3, 0, 4, 0, 0, 0, 0))

  @Test
  fun wireFormatIpv4HintTooLong() =
    assertWireParseFails(byteArrayOf(0, 1, 0, 0, 4, 0, 5, 1, 2, 3, 4, 5))

  @Test
  fun wireFormatIpv6HintTooShort() = assertWireParseFails(byteArrayOf(0, 1, 0, 0, 6, 0, 2, 1, 2))

  private fun assertRoundTrip(str: String) = assertEquals(str, stringToWireToString(str))

  private fun assertTextParseFails(str: String) {
    assertThrows<TextParseException> { stringToWire(str) }
  }

  private fun assertWireParseFails(wire: ByteArray) {
    assertThrows<WireParseException> { wireToString(wire) }
  }

  companion object {
    @JvmStatic
    fun stringToWire(str: String): ByteArray {
      val tokenizer = Tokenizer(str)
      val record = SVCBRecord()
      record.rdataFromString(tokenizer, null)
      val output = DNSOutput()
      record.rrToWire(output, null, true)
      return output.toByteArray()
    }

    @JvmStatic
    fun wireToString(bytes: ByteArray): String {
      val input = DNSInput(bytes)
      val record = SVCBRecord()
      record.rrFromWire(input)
      return record.rdataToString()
    }

    @JvmStatic fun stringToWireToString(str: String): String = wireToString(stringToWire(str))
  }
}
