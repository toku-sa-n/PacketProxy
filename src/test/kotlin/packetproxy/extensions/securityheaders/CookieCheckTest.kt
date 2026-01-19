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

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import packetproxy.extensions.securityheaders.checks.CookieCheck

class CookieCheckTest {
  private lateinit var check: CookieCheck
  private lateinit var context: MutableMap<String, Any>

  @BeforeEach
  fun setUp() {
    check = CookieCheck()
    context = mutableMapOf()
  }

  // ===== No Cookie Cases =====

  @Test
  fun testCheck_NoCookies_Ok() {
    val header = TestHttpHeader.empty()
    val result = check.check(header, context)

    assertTrue(result.isOk())
    assertEquals("No cookies", result.getDisplayValue())
  }

  // ===== Missing Secure Flag =====

  @Test
  fun testCheck_CookieWithoutSecure_Fail() {
    val header = TestHttpHeader.withSetCookie("session=abc123; HttpOnly")
    val result = check.check(header, context)

    assertTrue(result.isFail())
  }

  @Test
  fun testCheck_CookieWithHttpOnlyOnly_Fail() {
    val header = TestHttpHeader.withSetCookie("token=xyz; HttpOnly; Path=/")
    val result = check.check(header, context)

    assertTrue(result.isFail())
  }

  @Test
  fun testCheck_SimpleCookieWithoutAttributes_Fail() {
    val header = TestHttpHeader.withSetCookie("name=value")
    val result = check.check(header, context)

    assertTrue(result.isFail())
  }

  // ===== Multiple Cookies - Mixed Secure Status =====

  @Test
  fun testCheck_MultipleCookies_OneWithoutSecure_Fail() {
    val header =
      TestHttpHeader()
        .addHeader("Set-Cookie", "cookie1=value1; Secure")
        .addHeader("Set-Cookie", "cookie2=value2; HttpOnly")
        .build()
    val result = check.check(header, context)

    assertTrue(result.isFail())
  }

  @Test
  fun testCheck_MultipleCookies_AllWithoutSecure_Fail() {
    val header =
      TestHttpHeader()
        .addHeader("Set-Cookie", "cookie1=value1")
        .addHeader("Set-Cookie", "cookie2=value2")
        .addHeader("Set-Cookie", "cookie3=value3")
        .build()
    val result = check.check(header, context)

    assertTrue(result.isFail())
  }

  // ===== Edge Cases with Secure Flag Position =====

  @Test
  fun testCheck_SecureAtBeginning_Fail() {
    // Malformed: "Secure" at beginning without space prefix
    val header = TestHttpHeader.withSetCookie("Secure; session=abc123")
    val result = check.check(header, context)

    // Implementation checks for " secure" (with space), so this fails
    assertTrue(result.isFail())
  }

  @Test
  fun testCheck_SecureInValue_Fail() {
    // "secure" appears in cookie value, not as attribute
    val header = TestHttpHeader.withSetCookie("data=this_is_secure_data")
    val result = check.check(header, context)

    assertTrue(result.isFail()) // " secure" (with space) not found
  }

  @Test
  fun testCheck_SecureFlagWithDifferentCase_Ok() {
    val header = TestHttpHeader.withSetCookie("session=abc123; SECURE")
    val result = check.check(header, context)

    assertTrue(result.isOk())
  }

  @Test
  fun testCheck_SecureFlagMixedCase_Ok() {
    val header = TestHttpHeader.withSetCookie("session=abc123; SeCuRe")
    val result = check.check(header, context)

    assertTrue(result.isOk())
  }

  // ===== Valid Cookie Cases =====

  @Test
  fun testCheck_CookieWithSecure_Ok() {
    val header = TestHttpHeader.withSetCookie("session=abc123; Secure; HttpOnly")
    val result = check.check(header, context)

    assertTrue(result.isOk())
  }

  @Test
  fun testCheck_MultipleCookies_AllSecure_Ok() {
    val header =
      TestHttpHeader()
        .addHeader("Set-Cookie", "cookie1=value1; Secure")
        .addHeader("Set-Cookie", "cookie2=value2; Secure; HttpOnly")
        .build()
    val result = check.check(header, context)

    assertTrue(result.isOk())
  }

  // ===== Context Storage =====

  @Test
  fun testCheck_StoresCookiesInContext() {
    val header =
      TestHttpHeader()
        .addHeader("Set-Cookie", "cookie1=value1; Secure")
        .addHeader("Set-Cookie", "cookie2=value2")
        .build()
    check.check(header, context)

    @Suppress("UNCHECKED_CAST") val cookies = context[CookieCheck.CONTEXT_KEY] as List<String>
    assertNotNull(cookies)
    assertEquals(2, cookies.size)
  }

  @Test
  fun testCheck_NoCookies_StoresEmptyListInContext() {
    val header = TestHttpHeader.empty()
    check.check(header, context)

    @Suppress("UNCHECKED_CAST") val cookies = context[CookieCheck.CONTEXT_KEY] as List<String>
    assertNotNull(cookies)
    assertTrue(cookies.isEmpty())
  }

  // ===== Display Value Truncation =====

  @Test
  fun testCheck_LongCookieValue_Truncated() {
    val longValue = "a".repeat(100)
    val header = TestHttpHeader.withSetCookie("session=$longValue; Secure")
    val result = check.check(header, context)

    assertTrue(result.isOk())
    assertTrue(result.getDisplayValue().contains("..."))
  }

  // ===== Static hasSecureFlag Method =====

  @Test
  fun testHasSecureFlag_WithSecure_True() {
    assertTrue(CookieCheck.hasSecureFlag("set-cookie: session=abc; secure"))
  }

  @Test
  fun testHasSecureFlag_WithoutSecure_False() {
    assertFalse(CookieCheck.hasSecureFlag("set-cookie: session=abc; httponly"))
  }

  @Test
  fun testHasSecureFlag_EmptyString_False() {
    assertFalse(CookieCheck.hasSecureFlag(""))
  }

  @Test
  fun testHasSecureFlag_SecureInValue_True() {
    // Note: This is a known limitation - it checks for substring
    assertTrue(CookieCheck.hasSecureFlag("set-cookie: data=secure_value"))
  }

  // ===== matchesHeaderLine =====

  @Test
  fun testMatchesHeaderLine_SetCookie_True() {
    assertTrue(check.matchesHeaderLine("set-cookie: session=abc"))
  }

  @Test
  fun testMatchesHeaderLine_OtherHeader_False() {
    assertFalse(check.matchesHeaderLine("cookie: session=abc"))
  }

  @Test
  fun testMatchesHeaderLine_EmptyString_False() {
    assertFalse(check.matchesHeaderLine(""))
  }
}
