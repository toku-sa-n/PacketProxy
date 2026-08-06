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

class HTTPSRecordTest {
  @Test
  fun createParams() {
    val mandatoryList = listOf(HTTPSRecord.ALPN, HTTPSRecord.IPV4HINT)
    val mandatory = SVCBBase.ParameterMandatory(mandatoryList)
    assertEquals(HTTPSRecord.MANDATORY, mandatory.key)
    assertEquals(mandatoryList, mandatory.values)

    val alpnList = listOf("h2", "h3")
    val alpn = SVCBBase.ParameterAlpn(alpnList)
    assertEquals(HTTPSRecord.ALPN, alpn.key)
    assertEquals(alpnList, alpn.values)

    val port = SVCBBase.ParameterPort(8443)
    assertEquals(HTTPSRecord.PORT, port.key)
    assertEquals(8443, port.port)

    val ipv4List = listOf(InetAddress.getByName("1.2.3.4") as Inet4Address)
    val ipv4hint = SVCBBase.ParameterIpv4Hint(ipv4List)
    assertEquals(HTTPSRecord.IPV4HINT, ipv4hint.key)
    assertEquals(ipv4List, ipv4hint.addresses)

    val data = byteArrayOf('a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte())
    val echconfig = SVCBBase.ParameterEch(data)
    assertEquals(HTTPSRecord.ECH, echconfig.key)
    assertEquals(data, echconfig.data)

    val ipv6List = listOf(InetAddress.getByName("2001::1") as Inet6Address)
    val ipv6hint = SVCBBase.ParameterIpv6Hint(ipv6List)
    assertEquals(HTTPSRecord.IPV6HINT, ipv6hint.key)
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
    val record = HTTPSRecord(label, DClass.IN, 300, svcPriority, svcDomain, params)

    assertEquals(Type.HTTPS, record.type)
    assertEquals(label, record.name)
    assertEquals(svcPriority, record.svcPriority)
    assertEquals(svcDomain, record.targetName)
    assertEquals(
      listOf(HTTPSRecord.MANDATORY, HTTPSRecord.ALPN, HTTPSRecord.IPV4HINT).toString(),
      record.svcParamKeys.toString(),
    )
    assertEquals("alpn", record.getSvcParamValue(HTTPSRecord.MANDATORY).toString())
    assertEquals("h1,h2", record.getSvcParamValue(HTTPSRecord.ALPN).toString())
    assertEquals("h1,h2", record.getSvcParamValue(HTTPSRecord.ALPN).toString())
    assertNull(record.getSvcParamValue(1234))
    Options.unset("BINDTTL")
    Options.unset("noPrintIN")
    assertEquals(
      "test.com.\t\t300\tIN\tHTTPS\t5 svc.test.com. mandatory=alpn alpn=h1,h2 ipv4hint=1.2.3.4,5.6.7.8",
      record.toString(),
    )
  }

  @Test
  fun aliasMode() {
    val str = "0 a.b.c."
    val bytes = SVCBRecordTest.stringToWire(str)
    val expected =
      byteArrayOf(0, 0, 1, 'a'.code.toByte(), 1, 'b'.code.toByte(), 1, 'c'.code.toByte(), 0)
    assertArrayEquals(expected, bytes)
    assertEquals(str, SVCBRecordTest.wireToString(bytes))
  }

  @Test
  fun serviceModePort() {
    val str = "1 . port=8443"
    val bytes = SVCBRecordTest.stringToWire(str)
    val expected = byteArrayOf(0, 1, 0, 0, 3, 0, 2, 0x20, 0xFB.toByte())
    assertArrayEquals(expected, bytes)
    assertEquals(str, SVCBRecordTest.wireToString(bytes))
  }

  @Test
  fun serviceModeEchConfigMulti() {
    val str = "1 h3pool. alpn=h2,h3 echconfig=1234"
    assertEquals("1 h3pool. alpn=h2,h3 ech=1234", SVCBRecordTest.stringToWireToString(str))
  }

  @Test
  fun unknownKey() {
    val str = "1 . sport=8443"
    assertThrows<TextParseException> { SVCBRecordTest.stringToWire(str) }
  }
}
