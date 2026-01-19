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

/**
 * CORS check (Access-Control-Allow-Origin). Validates that wildcard (*) is not used and detects
 * potential Origin reflection.
 */
class CorsCheck : SecurityCheck {
  /** Context key for request Origin header */
  companion object {
    const val CONTEXT_KEY_REQUEST_ORIGIN = "requestOrigin"
  }

  private val MSG_WILDCARD = "Access-Control-Allow-Origin is set to '*' (wildcard)"
  private val MSG_ORIGIN_REFLECTION =
    "Access-Control-Allow-Origin may be reflecting the Origin header (potential misconfiguration)"

  private var currentMessage = MSG_WILDCARD

  override fun getName(): String = "CORS"

  override fun getColumnName(): String = "CORS"

  override fun getMissingMessage(): String = currentMessage

  override fun check(header: HttpHeader, context: MutableMap<String, Any>): SecurityCheckResult {
    val cors = header.getValue("Access-Control-Allow-Origin").orElse("")

    if (cors.isEmpty()) {
      return SecurityCheckResult.ok("No CORS", "")
    }

    if (cors == "*") {
      currentMessage = MSG_WILDCARD
      return SecurityCheckResult.fail(cors, cors)
    }

    // Check for Origin reflection
    val requestOrigin = context[CONTEXT_KEY_REQUEST_ORIGIN] as? String
    if (requestOrigin != null && requestOrigin.isNotEmpty() && cors == requestOrigin) {
      currentMessage = MSG_ORIGIN_REFLECTION
      return SecurityCheckResult.warn(cors, cors)
    }

    return SecurityCheckResult.ok(cors, cors)
  }

  override fun matchesHeaderLine(headerLine: String): Boolean {
    return headerLine.startsWith("access-control-allow-origin:")
  }

  override fun getGreenPatterns(): List<String> = listOf("access-control-allow-origin")

  override fun getYellowPatterns(): List<String> = listOf("access-control-allow-origin")

  override fun getRedPatterns(): List<String> = listOf("access-control-allow-origin: *")
}
