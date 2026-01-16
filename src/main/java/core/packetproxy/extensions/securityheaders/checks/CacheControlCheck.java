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
 * Cache-Control check. Validates secure cache configuration for sensitive data.
 */
public class CacheControlCheck implements SecurityCheck {

	@Override
	public String getName() {
		return "Cache-Control";
	}

	@Override
	public String getColumnName() {
		return "Cache-Control";
	}

	@Override
	public String getMissingMessage() {
		return "Cache-Control is not configured for sensitive data protection";
	}

	@Override
	public SecurityCheckResult check(HttpHeader header, Map<String, Object> context) {
		String cache = header.getValue("Cache-Control").orElse("");
		String pragma = header.getValue("Pragma").orElse("");

		boolean isSecure = cache.contains("private") && cache.contains("no-store") && cache.contains("no-cache")
				&& cache.contains("must-revalidate") && pragma.contains("no-cache");

		if (isSecure) {
			return SecurityCheckResult.ok(cache, cache);
		} else {
			if (cache.isEmpty() && pragma.isEmpty()) {
				return SecurityCheckResult.ok("No Cache-Control or Pragma", "");
			} else {
				return SecurityCheckResult.warn(cache, cache);
			}
		}
	}

	@Override
	public boolean matchesHeaderLine(String headerLine) {
		return headerLine.startsWith("cache-control:");
	}

	@Override
	public boolean affectsOverallStatus() {
		// Cache-Control doesn't affect overall pass/fail
		return false;
	}

	@Override
	public List<String> getYellowPatterns() {
		return Arrays.asList("cache-control:");
	}
}
