/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.http

import packetproxy.util.Logging.err
import packetproxy.util.Logging.errWithStackTrace

class HeaderField {
  private var _name = ""
  private var _value = ""

  constructor(rawLine: String) {
    val fields = rawLine.split(":", limit = 2)
    if (fields.size == 2) {
      _name = fields[0].trim()
      _value = fields[1].trim()
      return
    }
    err("invalid header field")
    errWithStackTrace(Throwable())
  }

  constructor(name: String, value: String) {
    this._name = name
    this._value = value
  }

  fun getName(): String = _name

  fun getValue(): String = _value

  override fun toString(): String = "$_name: $_value"
}
