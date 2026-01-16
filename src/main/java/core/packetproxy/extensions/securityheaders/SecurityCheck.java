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
package packetproxy.extensions.securityheaders;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import packetproxy.http.HttpHeader;

/**
 * Interface for security header checks. Implement this interface to add custom
 * security header validation rules.
 */
public interface SecurityCheck {

	/**
	 * Get the display name for this check (shown in issues pane)
	 *
	 * @return Display name (e.g., "CSP", "XSS Protection")
	 */
	String getName();

	/**
	 * Get the column name for the table
	 *
	 * @return Column name (e.g., "CSP", "XSS")
	 */
	String getColumnName();

	/**
	 * Get the error message when this check fails
	 *
	 * @return Error message describing the issue
	 */
	String getMissingMessage();

	/**
	 * Perform the security check
	 *
	 * @param header
	 *            The HTTP response header to check
	 * @param context
	 *            Shared context for checks that depend on other checks' results
	 * @return The result of the check
	 */
	SecurityCheckResult check(HttpHeader header, Map<String, Object> context);

	/**
	 * Check if a header line matches this security check Used for color-coding
	 * headers in the display
	 *
	 * @param headerLine
	 *            The header line to check (lowercase)
	 * @return true if this check applies to the header line
	 */
	boolean matchesHeaderLine(String headerLine);

	/**
	 * Determine if this check affects the overall pass/fail status
	 *
	 * @return true if a failure should cause overall FAIL status
	 */
	default boolean affectsOverallStatus() {
		return true;
	}

	enum HighlightType {
		GREEN, RED, YELLOW, NONE
	}

	/** Represents a segment of text to highlight with a specific style. */
	class HighlightSegment {
		private final int start;
		private final int end;
		private final HighlightType type;

		public HighlightSegment(int start, int end, HighlightType type) {
			this.start = start;
			this.end = end;
			this.type = type;
		}

		public int getStart() {
			return start;
		}

		public int getEnd() {
			return end;
		}

		public HighlightType getType() {
			return type;
		}
	}

	default HighlightType getHighlightType(String headerLine, SecurityCheckResult result) {
		if (!matchesHeaderLine(headerLine.toLowerCase())) {
			return HighlightType.NONE;
		}
		if (result != null) {
			if (result.isOk()) {
				return HighlightType.GREEN;
			}
			if (result.isWarn()) {
				return HighlightType.YELLOW;
			}
			if (result.isFail()) {
				return HighlightType.RED;
			}
		}
		return HighlightType.NONE;
	}

	// ===== Pattern-based Highlighting =====
	// Override these methods to specify which patterns should be highlighted with
	// each color.
	// The default getHighlightSegments implementation will automatically find and
	// highlight
	// these patterns in the header line.

	/**
	 * Get patterns to highlight in red (dangerous/fail). Override this method to
	 * specify patterns that indicate security issues.
	 *
	 * @return List of patterns to highlight in red (case-insensitive matching)
	 */
	default List<String> getRedPatterns() {
		return Collections.emptyList();
	}

	/**
	 * Get patterns to highlight in yellow (warning). Override this method to
	 * specify patterns that indicate potential issues.
	 *
	 * @return List of patterns to highlight in yellow (case-insensitive matching)
	 */
	default List<String> getYellowPatterns() {
		return Collections.emptyList();
	}

	/**
	 * Get patterns to highlight in green (safe/ok). Override this method to specify
	 * patterns that indicate secure settings.
	 *
	 * @return List of patterns to highlight in green (case-insensitive matching)
	 */
	default List<String> getGreenPatterns() {
		return Collections.emptyList();
	}

	/**
	 * Get highlight segments for a header line. The default implementation uses
	 * getRedPatterns(), getYellowPatterns(), and getGreenPatterns() to
	 * automatically find and highlight matching patterns.
	 *
	 * <p>
	 * Color determination (patterns only shown when result matches):
	 *
	 * <ul>
	 * <li>getRedPatterns(): Only shown in red when result is FAIL
	 * <li>getYellowPatterns(): Only shown in yellow when result is WARN
	 * <li>getGreenPatterns(): Only shown in green when result is OK
	 * </ul>
	 *
	 * @param headerLine
	 *            The full header line (e.g., "content-security-policy: default-src
	 *            'self'")
	 * @param result
	 *            The result of this check
	 * @return List of segments to highlight, or empty list for default behavior
	 *         (whole line)
	 */
	default List<HighlightSegment> getHighlightSegments(String headerLine, SecurityCheckResult result) {
		if (!matchesHeaderLine(headerLine.toLowerCase())) {
			return Collections.emptyList();
		}

		List<String> redPatterns = getRedPatterns();
		List<String> yellowPatterns = getYellowPatterns();
		List<String> greenPatterns = getGreenPatterns();

		// If no patterns defined, use default whole-line behavior
		if (redPatterns.isEmpty() && yellowPatterns.isEmpty() && greenPatterns.isEmpty()) {
			return Collections.emptyList();
		}

		List<HighlightSegment> segments = new ArrayList<>();

		// Add segments only when check result matches the color
		// redPatterns: only shown when FAIL
		if (result != null && result.isFail()) {
			addSegmentsForPatterns(headerLine, redPatterns, HighlightType.RED, segments);
		}
		// yellowPatterns: only shown when WARN
		if (result != null && result.isWarn()) {
			addSegmentsForPatterns(headerLine, yellowPatterns, HighlightType.YELLOW, segments);
		}
		// greenPatterns: only shown when OK
		if (result != null && result.isOk()) {
			addSegmentsForPatterns(headerLine, greenPatterns, HighlightType.GREEN, segments);
		}

		return segments;
	}

	/**
	 * Helper method to find and add highlight segments for a list of patterns.
	 * Finds each pattern occurrence in the line and highlights only the matched
	 * pattern text.
	 */
	private static void addSegmentsForPatterns(String line, List<String> patterns, HighlightType type,
			List<HighlightSegment> segments) {
		if (line == null || patterns == null || patterns.isEmpty()) {
			return;
		}

		String lowerLine = line.toLowerCase();
		for (String pattern : patterns) {
			String lowerPattern = pattern.toLowerCase().trim();
			int index = 0;
			while ((index = lowerLine.indexOf(lowerPattern, index)) != -1) {
				int start = index;
				int end = index + lowerPattern.length();
				tryAddSegment(segments, start, end, type);
				index = end;
			}
		}
	}

	/** Add segment if no higher-priority overlap exists. */
	private static void tryAddSegment(List<HighlightSegment> segments, int start, int end, HighlightType type) {
		boolean hasHigherPriorityOverlap = segments.stream()
				.anyMatch(s -> isHigherPriority(s.getType(), type) && start < s.getEnd() && end > s.getStart());

		if (!hasHigherPriorityOverlap) {
			segments.removeIf(s -> !isHigherPriority(s.getType(), type) && start < s.getEnd() && end > s.getStart());
			segments.add(new HighlightSegment(start, end, type));
		}
	}

	/**
	 * Check if type1 has higher priority than type2. Priority: GREEN > YELLOW > RED
	 */
	private static boolean isHigherPriority(HighlightType type1, HighlightType type2) {
		int priority1 = getPriority(type1);
		int priority2 = getPriority(type2);
		return priority1 > priority2;
	}

	private static int getPriority(HighlightType type) {
		switch (type) {
			case GREEN :
				return 3;
			case YELLOW :
				return 2;
			case RED :
				return 1;
			default :
				return 0;
		}
	}
}
