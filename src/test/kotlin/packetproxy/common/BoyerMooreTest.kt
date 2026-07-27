/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.common

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BoyerMooreTest {
  @Test
  fun testEmptyPattern() {
    var boyerMoore = BoyerMoore(byteArrayOf())
    assertEquals(-1, boyerMoore.searchIn("Hello".toByteArray()))
    assertEquals(-1, boyerMoore.searchIn("Hello".toByteArray(), 1))
    assertEquals(-1, boyerMoore.searchIn("Hello".toByteArray(), 1, 3))
  }

  @Test
  fun testEmptyPatternAndEmptyText() {
    var boyerMoore = BoyerMoore(byteArrayOf())
    assertEquals(-1, boyerMoore.searchIn("".toByteArray()))
  }

  @Test
  fun testBasicCase() {
    var testString = "He says, 'hello world.'"
    var boyerMoore = BoyerMoore("hello".toByteArray())
    assertTrue(
      testString.substring(boyerMoore.searchIn(testString.toByteArray())).startsWith("hello")
    )
  }

  @Test
  fun testFirstOccurrence() {
    var testString = "hell hello hello world"
    var boyerMoore = BoyerMoore("hello".toByteArray())
    assertTrue(
      testString.substring(boyerMoore.searchIn(testString.toByteArray())).startsWith("hello h")
    )
  }

  @Test
  fun testOffset() {
    var testString = "'Hello world.' And he smiled and said Hello Work."
    var boyerMoore = BoyerMoore("Hello".toByteArray())
    var index = boyerMoore.searchIn(testString.toByteArray(), 1)
    assertTrue(index == 0)
    index = boyerMoore.searchIn(testString.toByteArray(), 2)
    assertTrue(index == 36)
    assertTrue(testString.substring(38).startsWith("Hello Work"))
  }

  @Test
  fun testOutOfBoundsOffset() {
    var testString = "'Hello world.' And he smiled and said Hello Work."
    var boyerMoore = BoyerMoore("Hello".toByteArray())
    assertThrows(ArrayIndexOutOfBoundsException::class.java) {
      boyerMoore.searchIn(testString.toByteArray(), -1)
    }
    assertThrows(ArrayIndexOutOfBoundsException::class.java) {
      boyerMoore.searchIn(testString.toByteArray(), testString.length - "Hello".toByteArray().size)
    }
  }

  @Test
  fun testEndpos() {
    var testString = "'Hello world.' And he smiled and said Hello Work."
    var boyerMoore = BoyerMoore("Hello".toByteArray())
    var index = boyerMoore.searchIn(testString.toByteArray(), 2)
    assertTrue(index == 36)
    index = boyerMoore.searchIn(testString.toByteArray(), 2, 43)
    assertTrue(index == 36)
    index = boyerMoore.searchIn(testString.toByteArray(), 2, 42)
    assertTrue(index == -1)
  }

  @Test
  fun testMultiByte() {
    var testString = "こんにちは世界。さよなら人類。"
    var boyerMoore = BoyerMoore("世界".toByteArray())
    assertEquals("こんにちは".toByteArray().size, boyerMoore.searchIn(testString.toByteArray()))
  }

  @Test
  fun testFindHostHeader() {
    var header =
      "GET /v1/get_list?app_id=hoge&version=0.20.1 HTTP/1.1\r\n" +
        "Authorization: Basic hogehogehoge\r\n" +
        "Host: www.example.com:4444\r\n" +
        "Accept: */*\r\n\r\n"
    var pattern = "Host:"
    var boyerMoore = BoyerMoore(pattern.toByteArray())
    assertEquals(header.indexOf(pattern), boyerMoore.searchIn(header.toByteArray()))
  }
}
