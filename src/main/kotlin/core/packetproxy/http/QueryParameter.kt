/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.http

class QueryParameter {
  private var name: String? = null
  private var value: String? = null

  constructor(string: String) {
    val fields = string.split("=", limit = 2)
    if (fields.size == 2) {
      name = fields[0].trim()
      value = fields[1].trim()
    } else if (fields.size == 1) {
      name = fields[0].trim()
    }
  }

  constructor(name: String, value: String) {
    this.name = name
    this.value = value
  }

  fun getName(): String? = name

  fun getValue(): String? = value

  fun setValue(value: String?) {
    this.value = value
  }

  override fun toString(): String =
    when {
      name != null && value != null -> "$name=$value"
      name != null -> name!!
      else -> ""
    }
}
