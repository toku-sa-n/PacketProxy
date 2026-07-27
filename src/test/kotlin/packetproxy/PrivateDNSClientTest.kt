/*
 * Copyright 2022 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import java.net.InetAddress
import java.net.InetSocketAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.xbill.DNS.Name
import org.xbill.DNS.ResolverConfig
import org.xbill.DNS.config.ResolverConfigProvider

class PrivateDNSClientTest {
  @Test
  fun 成功するケース() {
    assertTrue(
      PrivateDNSClient.dnsLoopingFromHostsLines(
        listOf("127.0.0.1 aaa aaa.example.com # for test"),
        "aaa.example.com",
      )
    )
  }

  @Test
  fun 成功するケース2() {
    assertTrue(
      PrivateDNSClient.dnsLoopingFromHostsLines(
        listOf("2.3.4.5 aaa bbb.example.com", "127.0.0.1 aaa aaa.example.com"),
        "aaa.example.com",
      )
    )
  }

  @Test
  fun 成功するケース3() {
    assertTrue(
      PrivateDNSClient.dnsLoopingFromHostsLines(
        listOf(
          " # this is a comment.",
          "# 2.3.4.5 aaa bbb.example.com",
          "127.0.0.1 aaa aaa.example.com",
          " # 3.3.3.3 aaa ccc.example.com",
        ),
        "aaa.example.com",
      )
    )
  }

  @Test
  fun 失敗するケース() {
    assertFalse(
      PrivateDNSClient.dnsLoopingFromHostsLines(
        listOf("127.0.0.2 aaa aaa.example.com # for test"),
        "aaa.example.com",
      )
    )
  }

  @Test
  fun 失敗するケース2() {
    assertFalse(
      PrivateDNSClient.dnsLoopingFromHostsLines(
        listOf("# 127.0.0.2 aaa aaa.example.com"),
        "aaa.example.com",
      )
    )
  }

  @Test
  fun 失敗するケース3() {
    assertFalse(
      PrivateDNSClient.dnsLoopingFromHostsLines(
        listOf("# 127.0.0.2 aaa bbb.example.com"),
        "aaa.example.com",
      )
    )
  }

  @Test
  fun 失敗するケース4() {
    assertFalse(
      PrivateDNSClient.dnsLoopingFromHostsLines(
        listOf(
          " # this is a comment.",
          "# 2.3.4.5 aaa bbb.example.com",
          "127.0.0.1 aaa ddd.example.com",
          " # 3.3.3.3 aaa ccc.example.com",
        ),
        "aaa.example.com",
      )
    )
  }

  @Test
  fun システムDNS設定を再読込する() {
    val originalProviders = ResolverConfig.getConfigProviders()
    val provider = TestResolverConfigProvider("127.0.0.1")
    try {
      ResolverConfig.setConfigProviders(listOf(provider))
      ResolverConfig.refresh()
      provider.setServer("8.8.8.8")
      assertEquals("8.8.8.8", PrivateDNSClient.getCurrentSystemDnsServerAddress())
    } finally {
      ResolverConfig.setConfigProviders(originalProviders)
      ResolverConfig.refresh()
    }
  }

  private class TestResolverConfigProvider(server: String) : ResolverConfigProvider {
    private var servers: List<InetSocketAddress> = emptyList()

    init {
      setServer(server)
    }

    fun setServer(server: String) {
      servers = listOf(InetSocketAddress(InetAddress.getByName(server), 53))
    }

    override fun initialize() = Unit

    override fun servers(): List<InetSocketAddress> = servers

    override fun searchPaths(): List<Name> = emptyList()
  }
}
