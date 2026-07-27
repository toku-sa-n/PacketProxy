/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.common

import com.google.re2j.Pattern

class CamelCase {
  companion object {
    @JvmStatic
    fun toCamelCase(string: String): String {
      var matcher = Pattern.compile("([a-zA-Z][a-zA-Z0-9]*)").matcher(string)
      var stringBuffer = StringBuffer()
      while (matcher.find()) matcher.appendReplacement(stringBuffer, toProperCase(matcher.group()))
      matcher.appendTail(stringBuffer)
      return stringBuffer.toString()
    }

    private fun toProperCase(string: String) =
      string.substring(0, 1).uppercase() + string.substring(1).lowercase()
  }
}
