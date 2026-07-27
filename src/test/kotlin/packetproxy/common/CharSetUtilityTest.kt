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
package packetproxy.common

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import packetproxy.util.CharSetUtility

class CharSetUtilityTest {
  @Test
  fun testCountChar() {
    val header =
      "HTTP/1.1 302 Moved Temporarily\nContent-Type: text/html; charset=utf-8\nConnection: keep-alive\n"
    val a = CharSetUtility.getInstance().guessCharSetFromHttpHeader(header.toByteArray())
    assertEquals("utf-8", a)
    val header2 = "HTTP/1.1 302 Moved Temporarily\nContent-Type: text/html; charset=utf-8"
    val a2 = CharSetUtility.getInstance().guessCharSetFromHttpHeader(header2.toByteArray())
    assertEquals("utf-8", a2)

    val html5 = "<html>\n<head>\n<meta charset=\"UTF-8\">\n<title>test</title></head></html>"
    val b = CharSetUtility.getInstance().guessCharSetFromMetatag(html5.toByteArray())
    assertEquals("UTF-8", b)
    val html4 =
      "<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n<title>test</title></head></html>"
    val c = CharSetUtility.getInstance().guessCharSetFromMetatag(html4.toByteArray())
    assertEquals("UTF-8", c)
    val html4_2 =
      "<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8;\">\n<title>test</title></head></html>"
    val c2 = CharSetUtility.getInstance().guessCharSetFromMetatag(html4_2.toByteArray())
    assertEquals("UTF-8", c2)
    val html4_3 =
      "<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"charset=UTF-8;text/html\">\n<title>test</title></head></html>"
    val c3 = CharSetUtility.getInstance().guessCharSetFromMetatag(html4_2.toByteArray())
    assertEquals("UTF-8", c3)
  }
}
