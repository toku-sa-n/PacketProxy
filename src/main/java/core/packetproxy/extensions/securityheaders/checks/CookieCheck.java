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
 * Cookie security check (Set-Cookie). Validates that Secure flag is set on all
 * cookies.
 */
public class CookieCheck implements SecurityCheck {

	public static final String CONTEXT_KEY = "cookies";

	@Override
	public String getName() {
		return "Cookies";
	}

	@Override
	public String getColumnName() {
		return "Cookies";
	}

	@Override
	public String getMissingMessage() {
		return "Set-Cookie is missing 'Secure' flag";
	}

	@Override
	public SecurityCheckResult check(HttpHeader header, Map<String, Object> context) {
		List<String> setCookies = header.getAllValue("Set-Cookie");

		// Store cookies in context for detailed display
		context.put(CONTEXT_KEY, setCookies);

		if (setCookies.isEmpty()) {
			return SecurityCheckResult.ok("No cookies", "");
		}

		boolean allSecure = true;
		StringBuilder displayBuilder = new StringBuilder();

		for (String cookie : setCookies) {
			if (!cookie.toLowerCase().contains(" secure")) {
				allSecure = false;
			}

			// Truncate for display
			String truncated = cookie.length() > 100 ? cookie.substring(0, 100) + "..." : cookie;
			displayBuilder.append(truncated).append("; ");
		}

		String displayValue = displayBuilder.toString();
		String rawValue = String.join("; ", setCookies);

		if (allSecure) {
			return SecurityCheckResult.ok(displayValue, rawValue);
		} else {
			return SecurityCheckResult.fail(displayValue, rawValue);
		}
	}

	@Override
	public List<String> getGreenPatterns() {
		return Arrays.asList("set-cookie:", "secure");
	}

	@Override
	public boolean matchesHeaderLine(String headerLine) {
		return headerLine.startsWith("set-cookie:");
	}

	/** Check if a specific cookie line has the Secure flag */
	public static boolean hasSecureFlag(String cookieLine) {
		return cookieLine.toLowerCase().contains("secure");
	}
}
