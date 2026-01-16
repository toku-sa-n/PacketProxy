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
package packetproxy.extensions.securityheaders.checks;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import packetproxy.extensions.securityheaders.SecurityCheck;
import packetproxy.extensions.securityheaders.SecurityCheckResult;
import packetproxy.http.HttpHeader;

/**
 * Content-Security-Policy (CSP) check. Validates that frame-ancestors directive
 * is properly set to prevent clickjacking.
 */
public class CspCheck implements SecurityCheck {

	public static final String CONTEXT_KEY = "csp";

	@Override
	public String getName() {
		return "Content-Security-Policy";
	}

	@Override
	public String getColumnName() {
		return "CSP";
	}

	@Override
	public String getMissingMessage() {
		return "Content-Security-Policy with frame-ancestors or X-Frame-Options is missing";
	}

	@Override
	public SecurityCheckResult check(HttpHeader header, Map<String, Object> context) {
		String csp = header.getValue("Content-Security-Policy").orElse("");
		String xfo = header.getValue("X-Frame-Options").orElse("");

		// Store CSP value in context for other checks that depend on it
		context.put(CONTEXT_KEY, csp);

		boolean hasFrameAncestors = csp.contains("frame-ancestors 'none'") || csp.contains("frame-ancestors 'self'");

		if (hasFrameAncestors) {
			if (csp.contains("frame-ancestors 'none'")) {
				return SecurityCheckResult.ok("frame-ancestors 'none'", csp);
			}
			return SecurityCheckResult.ok("frame-ancestors 'self'", csp);
		}
		if (!xfo.isEmpty()) {
			return SecurityCheckResult.ok("X-Frame-Options:" + xfo, "X-Frame-Options: " + xfo);
		}

		if (csp.isEmpty()) {
			return SecurityCheckResult.fail("Missing", "");
		}

		return SecurityCheckResult.fail(csp, csp);
	}

	@Override
	public boolean matchesHeaderLine(String headerLine) {
		return headerLine.startsWith("content-security-policy:") || headerLine.startsWith("x-frame-options:");
	}

	@Override
	public HighlightType getHighlightType(String headerLine, SecurityCheckResult result) {
		// For X-Frame-Options, use the default whole-line highlighting
		String lowerLine = headerLine.toLowerCase();
		if (lowerLine.startsWith("x-frame-options:")) {
			return SecurityCheck.super.getHighlightType(headerLine, result);
		}
		// For CSP, we use segment-based highlighting instead
		return HighlightType.NONE;
	}

	// ===== Pattern-based Highlighting =====
	// Simply define which patterns should be highlighted with each color.
	// The base interface handles all the segment detection logic.

	@Override
	public List<String> getGreenPatterns() {
		return Arrays.asList("frame-ancestors 'none'", "frame-ancestors 'self'");
	}

	@Override
	public List<String> getRedPatterns() {
		return Arrays.asList("content-security-policy:");
	}
}
