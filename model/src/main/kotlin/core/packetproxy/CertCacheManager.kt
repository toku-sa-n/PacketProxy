/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import java.security.KeyStore
import packetproxy.model.CAs.CA

class CertCacheManager() {
  private val certCache = HashMap<String, KeyStore>()

  @Throws(Exception::class)
  fun getKeyStore(commonName: String, domainNames: Array<String>, ca: CA): KeyStore {
    synchronized(this) {
      val key = commonName + domainNames.joinToString(separator = "") + ca.getName()
      certCache[key]?.let {
        return it
      }
      return ca.createKeyStore(commonName, domainNames).also { certCache[key] = it }
    }
  }

  fun clearCache() {
    certCache.clear()
  }
}
