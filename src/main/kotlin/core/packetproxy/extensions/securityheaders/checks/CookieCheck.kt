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

/** Cookie security check (Set-Cookie). Validates that Secure flag is set on all cookies. */
class CookieCheck : SecurityCheck {
  companion object {
    const val CONTEXT_KEY = "cookies"

    /** Check if a specific cookie line has the Secure flag */
    @JvmStatic
    fun hasSecureFlag(cookieLine: String): Boolean {
      return cookieLine.lowercase().contains("secure")
    }
  }

  override fun getName(): String = "Cookies"

  override fun getColumnName(): String = "Cookies"

  override fun getMissingMessage(): String = "Set-Cookie is missing 'Secure' flag"

  override fun check(header: HttpHeader, context: MutableMap<String, Any>): SecurityCheckResult {
    val setCookies = header.getAllValue("Set-Cookie")

    // Store cookies in context for detailed display
    context[CONTEXT_KEY] = setCookies

    if (setCookies.isEmpty()) {
      return SecurityCheckResult.ok("No cookies", "")
    }

    var allSecure = true
    val displayBuilder = StringBuilder()

    for (cookie in setCookies) {
      if (!cookie.lowercase().contains(" secure")) {
        allSecure = false
      }

      // Truncate for display
      val truncated = if (cookie.length > 100) cookie.substring(0, 100) + "..." else cookie
      displayBuilder.append(truncated).append("; ")
    }

    val displayValue = displayBuilder.toString()
    val rawValue = setCookies.joinToString("; ")

    return if (allSecure) {
      SecurityCheckResult.ok(displayValue, rawValue)
    } else {
      SecurityCheckResult.fail(displayValue, rawValue)
    }
  }

  override fun getGreenPatterns(): List<String> = listOf("set-cookie:", "secure")

  override fun matchesHeaderLine(headerLine: String): Boolean {
    return headerLine.startsWith("set-cookie:")
  }
}
