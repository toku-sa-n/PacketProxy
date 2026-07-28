/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import java.lang.reflect.Modifier
import java.nio.file.Paths
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.StandardLocation
import javax.tools.ToolProvider
import packetproxy.ppcontextmenu.PPContextMenu
import packetproxy.util.errWithStackTrace

class PPContextMenuManager {
  private var moduleList = ArrayList<PPContextMenu>()

  init {
    try {
      loadItems()
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  fun getMenuItemList(): List<PPContextMenu> = moduleList

  @Throws(Exception::class)
  private fun loadItems() {
    val compiler = ToolProvider.getSystemJavaCompiler()
    val fileManager =
      compiler.getStandardFileManager(DiagnosticCollector<JavaFileObject>(), null, null)
    val kinds = setOf(JavaFileObject.Kind.CLASS)
    for (file in fileManager.list(StandardLocation.CLASS_PATH, ITEM_PACKAGE, kinds, false)) {
      val className =
        "$ITEM_PACKAGE.${Paths.get(file.name).fileName.toString().replace(Regex("\\.class.*$"), "")}"
      val klass = Class.forName(className)
      if (
        !PPContextMenu::class.java.isAssignableFrom(klass) || Modifier.isAbstract(klass.modifiers)
      )
        continue
      moduleList.add(createInstance(klass.asSubclass(PPContextMenu::class.java)))
    }
  }

  @Throws(Exception::class)
  private fun createInstance(klass: Class<out PPContextMenu>): PPContextMenu =
    klass.getDeclaredConstructor().newInstance()

  companion object {
    private val ITEM_PACKAGE = "packetproxy.ppcontextmenu"
  }
}
