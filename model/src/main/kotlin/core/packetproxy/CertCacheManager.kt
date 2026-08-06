/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import java.security.KeyStore
import java.util.LinkedHashMap
import packetproxy.model.CAs.CA

class CertCacheManager(private val maxSize: Int = 256) {
  private val certCache =
    object : LinkedHashMap<String, KeyStore>(16, 0.75f, true) {
      override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, KeyStore>?): Boolean =
        size > maxSize
    }

  @Throws(Exception::class)
  fun getKeyStore(commonName: String, domainNames: Array<String>, ca: CA): KeyStore {
    synchronized(this) {
      val key = buildKey(commonName, domainNames, ca)
      certCache[key]?.let {
        return it
      }
      return ca.createKeyStore(commonName, domainNames).also { certCache[key] = it }
    }
  }

  fun clearCache() {
    synchronized(this) { certCache.clear() }
  }

  private fun buildKey(commonName: String, domainNames: Array<String>, ca: CA): String =
    listOf(commonName, *domainNames, ca.getName()).joinToString(separator = "\u0000")
}
