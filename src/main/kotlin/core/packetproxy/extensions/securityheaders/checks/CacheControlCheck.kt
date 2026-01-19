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
package packetproxy.extensions.securityheaders.checks

import packetproxy.extensions.securityheaders.SecurityCheck
import packetproxy.extensions.securityheaders.SecurityCheckResult
import packetproxy.http.HttpHeader

/** Cache-Control check. Validates secure cache configuration for sensitive data. */
class CacheControlCheck : SecurityCheck {
  override fun getName(): String = "Cache-Control"

  override fun getColumnName(): String = "Cache-Control"

  override fun getMissingMessage(): String =
    "Cache-Control is not configured for sensitive data protection"

  override fun check(header: HttpHeader, context: MutableMap<String, Any>): SecurityCheckResult {
    val cache = header.getValue("Cache-Control").orElse("")
    val pragma = header.getValue("Pragma").orElse("")

    val isSecure =
      cache.contains("private") &&
        cache.contains("no-store") &&
        cache.contains("no-cache") &&
        cache.contains("must-revalidate") &&
        pragma.contains("no-cache")

    return if (isSecure) {
      SecurityCheckResult.ok(cache, cache)
    } else {
      if (cache.isEmpty() && pragma.isEmpty()) {
        SecurityCheckResult.ok("No Cache-Control or Pragma", "")
      } else {
        SecurityCheckResult.warn(cache, cache)
      }
    }
  }

  override fun matchesHeaderLine(headerLine: String): Boolean {
    return headerLine.startsWith("cache-control:")
  }

  override fun affectsOverallStatus(): Boolean {
    // Cache-Control doesn't affect overall pass/fail
    return false
  }

  override fun getYellowPatterns(): List<String> = listOf("cache-control:")
}
