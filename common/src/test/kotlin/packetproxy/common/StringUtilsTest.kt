/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.common

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class StringUtilsTest {
  @Test
  fun testCountChar() {
    var count = StringUtils.countChar("Hello", 'l', 0, "Hello".length)
    assertEquals(2, count)
    count = StringUtils.countChar("Hello", 'l', 3, "Hello".length)
    assertEquals(1, count)
    count = StringUtils.countChar("Hello", 'l', 0, 3)
    assertEquals(1, count)
    count = StringUtils.countChar("Hello", 'l', 3, 3)
    assertEquals(0, count)
    count = StringUtils.countChar("Hello", 'l', 4, 3)
    assertEquals(0, count)
  }
}
