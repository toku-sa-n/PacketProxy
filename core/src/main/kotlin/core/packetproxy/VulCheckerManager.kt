/*
 * Copyright 2021 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import com.google.common.collect.ImmutableMap
import java.lang.reflect.Modifier
import java.nio.file.Paths
import java.util.concurrent.atomic.AtomicBoolean
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.StandardLocation
import javax.tools.ToolProvider
import packetproxy.util.errWithStackTrace
import packetproxy.vulchecker.VulChecker

class VulCheckerManager {
  private val checkersLoaded = AtomicBoolean(false)
  private val vulCheckerMap = HashMap<String, Class<out VulChecker>>()

  fun getVulCheckerNameList(): Array<String> {
    ensureVulCheckersLoaded()
    return vulCheckerMap.keys.sorted().toTypedArray()
  }

  fun getAllVulCheckers(): ImmutableMap<String, Class<out VulChecker>> {
    ensureVulCheckersLoaded()
    return ImmutableMap.copyOf(vulCheckerMap)
  }

  @Throws(Exception::class)
  fun createInstance(vulCheckerName: String): VulChecker? {
    ensureVulCheckersLoaded()
    return vulCheckerMap[vulCheckerName]?.let { createInstance(it) }
  }

  @Throws(Exception::class)
  private fun loadVulCheckers() {
    val compiler = ToolProvider.getSystemJavaCompiler()
    val fileManager =
      compiler.getStandardFileManager(DiagnosticCollector<JavaFileObject>(), null, null)
    val kinds = setOf(JavaFileObject.Kind.CLASS)
    for (file in fileManager.list(StandardLocation.CLASS_PATH, VUL_CHECKER_PACKAGE, kinds, false)) {
      try {
        val className =
          "$VUL_CHECKER_PACKAGE.${Paths.get(file.name).fileName.toString().replace(Regex("\\.class.*$"), "")}"
        val klass = Class.forName(className)
        if (!VulChecker::class.java.isAssignableFrom(klass) || Modifier.isAbstract(klass.modifiers))
          continue
        val vulChecker = createInstance(klass.asSubclass(VulChecker::class.java))
        vulCheckerMap[vulChecker.getName()] = klass.asSubclass(VulChecker::class.java)
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }
  }

  @Throws(Exception::class)
  private fun createInstance(klass: Class<out VulChecker>): VulChecker =
    klass.getConstructor().newInstance()

  companion object {
    private val VUL_CHECKER_PACKAGE = "packetproxy.vulchecker"
  }

  private fun ensureVulCheckersLoaded() {
    if (!checkersLoaded.compareAndSet(false, true)) {
      return
    }
    try {
      loadVulCheckers()
    } catch (exception: Exception) {
      checkersLoaded.set(false)
      errWithStackTrace(exception)
    }
  }
}
