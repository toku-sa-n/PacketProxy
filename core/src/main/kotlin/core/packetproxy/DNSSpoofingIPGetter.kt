/*
 * Copyright 2026 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

class DNSSpoofingIPGetter(private val config: DnsSpoofingConfig) {
  fun isAuto(): Boolean = config.isAutoSpoofing()

  fun get(): String = config.getSpoofingIP()

  fun get6(): String = config.getSpoofingIP6()

  fun getInt(): String = config.getBindInterface()
}
