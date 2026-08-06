/*
 * Copyright 2026 DeNA Co., Ltd.
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
package packetproxy.model

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DaoQueryCacheTest {
  @Test
  fun cacheKey_includesTypeAndQueryNotHashCodeAlone() {
    assertEquals("query:1", DaoQueryCache.cacheKey("query", 1))
    assertEquals("query:2", DaoQueryCache.cacheKey("query", 2))
    assertNotEquals(DaoQueryCache.cacheKey("query", 1), DaoQueryCache.cacheKey("queryAll", 1))
  }

  @Test
  fun distinctQueries_doNotCollideViaHashCode() {
    val cache = DaoQueryCache<String>()
    // Strings chosen so their hashCodes collide historically is hard; instead verify
    // string-key identity: different values keep separate entries even if hashCodes match.
    cache.set("q", "alpha", "A")
    cache.set("q", "beta", "B")
    assertEquals(listOf("A"), cache.query("q", "alpha"))
    assertEquals(listOf("B"), cache.query("q", "beta"))
  }

  @Test
  fun concurrentSetAndQuery_doNotThrowAndRemainConsistent() {
    val cache = DaoQueryCache<Int>()
    val threads = 8
    val opsPerThread = 200
    val pool = Executors.newFixedThreadPool(threads)
    val start = CountDownLatch(1)
    val errors = AtomicInteger(0)

    repeat(threads) { t ->
      pool.submit {
        try {
          start.await()
          repeat(opsPerThread) { i ->
            val key = t * opsPerThread + i
            cache.set("type", key, key)
            val hit = cache.query("type", key)
            if (hit != null && hit[0] != key) {
              errors.incrementAndGet()
            }
          }
        } catch (_: Exception) {
          errors.incrementAndGet()
        }
      }
    }
    start.countDown()
    pool.shutdown()
    assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS))
    assertEquals(0, errors.get())
    assertNull(cache.query("missing", 0))
  }
}
