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
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.StandardLocation
import javax.tools.ToolProvider
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.vulchecker.VulChecker

class VulCheckerManager private constructor() {
  private val vulCheckerMap = HashMap<String, Class<out VulChecker>>()

  init {
    try {
      loadVulCheckers()
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  fun getVulCheckerNameList(): Array<String> = vulCheckerMap.keys.sorted().toTypedArray()

  fun getAllVulCheckers(): ImmutableMap<String, Class<out VulChecker>> =
    ImmutableMap.copyOf(vulCheckerMap)

  @Throws(Exception::class)
  fun createInstance(vulCheckerName: String): VulChecker? =
    vulCheckerMap[vulCheckerName]?.let { createInstance(it) }

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
    private const val VUL_CHECKER_PACKAGE = "packetproxy.vulchecker"
    private var instance: VulCheckerManager? = null

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): VulCheckerManager {
      if (instance == null) instance = VulCheckerManager()
      return instance!!
    }
  }
}
