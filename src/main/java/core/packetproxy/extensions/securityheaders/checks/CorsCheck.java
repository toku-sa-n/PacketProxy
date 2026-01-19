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
 * CORS check (Access-Control-Allow-Origin). Validates that wildcard (*) is not
 * used and detects potential Origin reflection.
 */
public class CorsCheck implements SecurityCheck {

	/** Context key for request Origin header */
	public static final String CONTEXT_KEY_REQUEST_ORIGIN = "requestOrigin";

	private static final String MSG_WILDCARD = "Access-Control-Allow-Origin is set to '*' (wildcard)";
	private static final String MSG_ORIGIN_REFLECTION = "Access-Control-Allow-Origin may be reflecting the Origin header (potential misconfiguration)";

	private String currentMessage = MSG_WILDCARD;

	@Override
	public String getName() {
		return "CORS";
	}

	@Override
	public String getColumnName() {
		return "CORS";
	}

	@Override
	public String getMissingMessage() {
		return currentMessage;
	}

	@Override
	public SecurityCheckResult check(HttpHeader header, Map<String, Object> context) {
		String cors = header.getValue("Access-Control-Allow-Origin").orElse("");

		if (cors.isEmpty()) {
			return SecurityCheckResult.ok("No CORS", "");
		}

		if (cors.equals("*")) {
			currentMessage = MSG_WILDCARD;
			return SecurityCheckResult.fail(cors, cors);
		}

		// Check for Origin reflection
		String requestOrigin = (String) context.get(CONTEXT_KEY_REQUEST_ORIGIN);
		if (requestOrigin != null && !requestOrigin.isEmpty() && cors.equals(requestOrigin)) {
			currentMessage = MSG_ORIGIN_REFLECTION;
			return SecurityCheckResult.warn(cors, cors);
		}

		return SecurityCheckResult.ok(cors, cors);
	}

	@Override
	public boolean matchesHeaderLine(String headerLine) {
		return headerLine.startsWith("access-control-allow-origin:");
	}

	@Override
	public List<String> getGreenPatterns() {
		return Arrays.asList("access-control-allow-origin");
	}

	@Override
	public List<String> getYellowPatterns() {
		return Arrays.asList("access-control-allow-origin");
	}

	@Override
	public List<String> getRedPatterns() {
		return Arrays.asList("access-control-allow-origin: *");
	}
}
