/*
 * Copyright 2026 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

interface DnsSpoofingConfig {
  fun isAutoSpoofing(): Boolean

  fun getSpoofingIP(): String

  fun getSpoofingIP6(): String

  fun getBindInterface(): String
}
