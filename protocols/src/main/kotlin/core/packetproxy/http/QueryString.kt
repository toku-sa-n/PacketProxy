/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.http

import java.util.Optional
import java.util.function.Function
import java.util.function.Predicate
import java.util.stream.Stream

class QueryString(query: String) {
  private var params: List<QueryParameter> = query.split("&").map { QueryParameter(it) }

  override fun toString(): String = params.joinToString("&") { it.toString() }

  fun getParam(name: String): Optional<QueryParameter> =
    params.stream().filter { p -> p.getName() == name }.findFirst()

  fun getValue(name: String): Optional<String> {
    var param = getParam(name)
    return if (param.isPresent) {
      Optional.ofNullable(param.get().getValue())
    } else {
      Optional.empty()
    }
  }

  fun filter(predicate: Predicate<in QueryParameter>): Stream<QueryParameter> =
    params.stream().filter(predicate)

  fun <R> map(mapper: Function<in QueryParameter, out R>): Stream<R> = params.stream().map(mapper)

  fun update(name: String, value: String) {
    params
      .stream()
      .filter { p -> p.getName() == name }
      .findFirst()
      .ifPresent { p -> p.setValue(value) }
  }
}
