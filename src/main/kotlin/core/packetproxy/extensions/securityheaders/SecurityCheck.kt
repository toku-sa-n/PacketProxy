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
package packetproxy.extensions.securityheaders

import packetproxy.http.HttpHeader

/**
 * Interface for security header checks. Implement this interface to add custom security header
 * validation rules.
 */
interface SecurityCheck {
  /**
   * Get the display name for this check (shown in issues pane)
   *
   * @return Display name (e.g., "CSP", "XSS Protection")
   */
  fun getName(): String

  /**
   * Get the column name for the table
   *
   * @return Column name (e.g., "CSP", "XSS")
   */
  fun getColumnName(): String

  /**
   * Get the error message when this check fails
   *
   * @return Error message describing the issue
   */
  fun getMissingMessage(): String

  /**
   * Perform the security check
   *
   * @param header The HTTP response header to check
   * @param context Shared context for checks that depend on other checks' results
   * @return The result of the check
   */
  fun check(header: HttpHeader, context: MutableMap<String, Any>): SecurityCheckResult

  /**
   * Check if a header line matches this security check Used for color-coding headers in the display
   *
   * @param headerLine The header line to check (lowercase)
   * @return true if this check applies to the header line
   */
  fun matchesHeaderLine(headerLine: String): Boolean

  /**
   * Determine if this check affects the overall pass/fail status
   *
   * @return true if a failure should cause overall FAIL status
   */
  fun affectsOverallStatus(): Boolean = true

  enum class HighlightType {
    GREEN,
    RED,
    YELLOW,
    NONE,
  }

  /** Represents a segment of text to highlight with a specific style. */
  data class HighlightSegment(val start: Int, val end: Int, val type: HighlightType)

  fun getHighlightType(headerLine: String, result: SecurityCheckResult?): HighlightType {
    if (!matchesHeaderLine(headerLine.lowercase())) {
      return HighlightType.NONE
    }
    return when {
      result == null -> HighlightType.NONE
      result.isOk() -> HighlightType.GREEN
      result.isWarn() -> HighlightType.YELLOW
      result.isFail() -> HighlightType.RED
      else -> HighlightType.NONE
    }
  }

  // ===== Pattern-based Highlighting =====
  // Override these methods to specify which patterns should be highlighted with
  // each color.
  // The default getHighlightSegments implementation will automatically find and
  // highlight
  // these patterns in the header line.

  /**
   * Get patterns to highlight in red (dangerous/fail). Override this method to specify patterns
   * that indicate security issues.
   *
   * @return List of patterns to highlight in red (case-insensitive matching)
   */
  fun getRedPatterns(): List<String> = emptyList()

  /**
   * Get patterns to highlight in yellow (warning). Override this method to specify patterns that
   * indicate potential issues.
   *
   * @return List of patterns to highlight in yellow (case-insensitive matching)
   */
  fun getYellowPatterns(): List<String> = emptyList()

  /**
   * Get patterns to highlight in green (safe/ok). Override this method to specify patterns that
   * indicate secure settings.
   *
   * @return List of patterns to highlight in green (case-insensitive matching)
   */
  fun getGreenPatterns(): List<String> = emptyList()

  /**
   * Get highlight segments for a header line. The default implementation uses getRedPatterns(),
   * getYellowPatterns(), and getGreenPatterns() to automatically find and highlight matching
   * patterns.
   *
   * <p>
   * Color determination (patterns only shown when result matches):
   * <ul>
   * <li>getRedPatterns(): Only shown in red when result is FAIL
   * <li>getYellowPatterns(): Only shown in yellow when result is WARN
   * <li>getGreenPatterns(): Only shown in green when result is OK
   * </ul>
   *
   * @param headerLine The full header line (e.g., "content-security-policy: default-src 'self'")
   * @param result The result of this check
   * @return List of segments to highlight, or empty list for default behavior (whole line)
   */
  fun getHighlightSegments(
    headerLine: String,
    result: SecurityCheckResult?,
  ): List<HighlightSegment> {
    if (!matchesHeaderLine(headerLine.lowercase())) {
      return emptyList()
    }

    val redPatterns = getRedPatterns()
    val yellowPatterns = getYellowPatterns()
    val greenPatterns = getGreenPatterns()

    // If no patterns defined, use default whole-line behavior
    if (redPatterns.isEmpty() && yellowPatterns.isEmpty() && greenPatterns.isEmpty()) {
      return emptyList()
    }

    val segments = mutableListOf<HighlightSegment>()

    // Add segments only when check result matches the color
    // redPatterns: only shown when FAIL
    if (result != null && result.isFail()) {
      addSegmentsForPatterns(headerLine, redPatterns, HighlightType.RED, segments)
    }
    // yellowPatterns: only shown when WARN
    if (result != null && result.isWarn()) {
      addSegmentsForPatterns(headerLine, yellowPatterns, HighlightType.YELLOW, segments)
    }
    // greenPatterns: only shown when OK
    if (result != null && result.isOk()) {
      addSegmentsForPatterns(headerLine, greenPatterns, HighlightType.GREEN, segments)
    }

    return segments
  }

  companion object {
    /**
     * Helper method to find and add highlight segments for a list of patterns. Finds each pattern
     * occurrence in the line and highlights only the matched pattern text.
     */
    private fun addSegmentsForPatterns(
      line: String,
      patterns: List<String>,
      type: HighlightType,
      segments: MutableList<HighlightSegment>,
    ) {
      if (line.isEmpty() || patterns.isEmpty()) {
        return
      }

      val lowerLine = line.lowercase()
      for (pattern in patterns) {
        val lowerPattern = pattern.lowercase().trim()
        var index = 0
        while (true) {
          index = lowerLine.indexOf(lowerPattern, index)
          if (index == -1) break
          val start = index
          val end = index + lowerPattern.length
          tryAddSegment(segments, start, end, type)
          index = end
        }
      }
    }

    /** Add segment if no higher-priority overlap exists. */
    private fun tryAddSegment(
      segments: MutableList<HighlightSegment>,
      start: Int,
      end: Int,
      type: HighlightType,
    ) {
      val hasHigherPriorityOverlap =
        segments.any { segment ->
          isHigherPriority(segment.type, type) && start < segment.end && end > segment.start
        }

      if (!hasHigherPriorityOverlap) {
        segments.removeIf { segment ->
          !isHigherPriority(segment.type, type) && start < segment.end && end > segment.start
        }
        segments.add(HighlightSegment(start, end, type))
      }
    }

    /** Check if type1 has higher priority than type2. Priority: GREEN > YELLOW > RED */
    private fun isHigherPriority(type1: HighlightType, type2: HighlightType): Boolean {
      return getPriority(type1) > getPriority(type2)
    }

    private fun getPriority(type: HighlightType): Int {
      return when (type) {
        HighlightType.GREEN -> 3
        HighlightType.YELLOW -> 2
        HighlightType.RED -> 1
        HighlightType.NONE -> 0
      }
    }
  }
}
