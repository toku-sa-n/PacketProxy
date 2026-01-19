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
package packetproxy.extensions.securityheaders.test;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import packetproxy.extensions.securityheaders.SecurityCheckResult;
import packetproxy.extensions.securityheaders.checks.CorsCheck;
import packetproxy.http.HttpHeader;

public class CorsCheckTest {

	private CorsCheck check;
	private Map<String, Object> context;

	@BeforeEach
	public void setUp() {
		check = new CorsCheck();
		context = new HashMap<>();
	}

	// ===== No CORS Header =====

	@Test
	public void testCheck_NoCorsHeader_Ok() {
		HttpHeader header = TestHttpHeader.empty();
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
		assertEquals("No CORS", result.getDisplayValue());
	}

	// ===== Wildcard CORS - Security Issue =====

	@Test
	public void testCheck_WildcardCors_Fail() {
		HttpHeader header = TestHttpHeader.withCors("*");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
		assertEquals("*", result.getDisplayValue());
	}

	// ===== Potentially Dangerous CORS Configurations =====

	@Test
	public void testCheck_WildcardWithSpace_Fail() {
		// " *" is trimmed to "*" by HttpHeader, so it fails
		HttpHeader header = TestHttpHeader.withCors(" *");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	@Test
	public void testCheck_MultipleWildcards_Ok() {
		// "**" is not exactly "*"
		HttpHeader header = TestHttpHeader.withCors("**");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_WildcardInUrl_Ok() {
		// Wildcard as part of URL is not the same as just "*"
		HttpHeader header = TestHttpHeader.withCors("https://*.example.com");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== Valid CORS Configurations =====

	@Test
	public void testCheck_SpecificOrigin_Ok() {
		HttpHeader header = TestHttpHeader.withCors("https://example.com");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
		assertEquals("https://example.com", result.getDisplayValue());
	}

	@Test
	public void testCheck_HttpOrigin_Ok() {
		HttpHeader header = TestHttpHeader.withCors("http://localhost:3000");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_NullOrigin_Ok() {
		// "null" origin is a special case, technically valid
		HttpHeader header = TestHttpHeader.withCors("null");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== Origin Reflection Detection =====

	@Test
	public void testCheck_OriginReflection_DevOrigin_Warn() {
		// Even dev origins should warn if reflected
		String origin = "https://dev.example.com";
		context.put(CorsCheck.CONTEXT_KEY_REQUEST_ORIGIN, origin);
		HttpHeader header = TestHttpHeader.withCors(origin);
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isWarn());
	}

	@Test
	public void testCheck_DifferentOrigin_Ok() {
		// When ACAO is different from request Origin, it's OK (static config)
		context.put(CorsCheck.CONTEXT_KEY_REQUEST_ORIGIN, "https://a.example.com");
		HttpHeader header = TestHttpHeader.withCors("https://b.example.com");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
		assertEquals("https://b.example.com", result.getDisplayValue());
	}

	@Test
	public void testCheck_NoRequestOrigin_Ok() {
		// When no Origin in request, can't detect reflection
		HttpHeader header = TestHttpHeader.withCors("https://example.com");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_EmptyRequestOrigin_Ok() {
		// Empty Origin in context should not trigger reflection warning
		context.put(CorsCheck.CONTEXT_KEY_REQUEST_ORIGIN, "");
		HttpHeader header = TestHttpHeader.withCors("https://example.com");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_WildcardStillFails_EvenWithOrigin() {
		// Wildcard should still fail even if Origin is present
		context.put(CorsCheck.CONTEXT_KEY_REQUEST_ORIGIN, "https://example.com");
		HttpHeader header = TestHttpHeader.withCors("*");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isFail());
	}

	// ===== Edge Cases =====

	@Test
	public void testCheck_EmptyCorsValue_Ok() {
		// Empty string is treated as no CORS
		HttpHeader header = TestHttpHeader.withCors("");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
		assertEquals("No CORS", result.getDisplayValue());
	}

	@Test
	public void testCheck_WhitespaceOnlyCors_Ok() {
		// Whitespace is not "*"
		HttpHeader header = TestHttpHeader.withCors("   ");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_CorsWithPort_Ok() {
		HttpHeader header = TestHttpHeader.withCors("https://example.com:8443");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	@Test
	public void testCheck_CorsWithPath_Ok() {
		// Technically invalid CORS (should be origin only), but check doesn't validate
		HttpHeader header = TestHttpHeader.withCors("https://example.com/path");
		SecurityCheckResult result = check.check(header, context);

		assertTrue(result.isOk());
	}

	// ===== matchesHeaderLine =====

	@Test
	public void testMatchesHeaderLine_Cors_True() {
		assertTrue(check.matchesHeaderLine("access-control-allow-origin: https://example.com"));
	}

	@Test
	public void testMatchesHeaderLine_OtherAcHeader_False() {
		assertFalse(check.matchesHeaderLine("access-control-allow-methods: GET, POST"));
	}

	@Test
	public void testMatchesHeaderLine_OtherHeader_False() {
		assertFalse(check.matchesHeaderLine("content-type: application/json"));
	}

	@Test
	public void testMatchesHeaderLine_EmptyString_False() {
		assertFalse(check.matchesHeaderLine(""));
	}

	// ===== Name and Messages =====

	@Test
	public void testGetName() {
		assertEquals("CORS", check.getName());
	}

	@Test
	public void testGetColumnName() {
		assertEquals("CORS", check.getColumnName());
	}

	@Test
	public void testGetMissingMessage() {
		assertEquals("Access-Control-Allow-Origin is set to '*' (wildcard)", check.getMissingMessage());
	}
}
