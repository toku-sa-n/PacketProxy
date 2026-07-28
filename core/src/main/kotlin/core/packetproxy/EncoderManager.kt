/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import java.io.File
import java.lang.reflect.Modifier
import java.net.URLClassLoader
import java.nio.file.Paths
import java.util.jar.JarFile
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.StandardLocation
import javax.tools.ToolProvider
import org.apache.commons.io.FilenameUtils
import packetproxy.encode.Encoder
import packetproxy.model.Packet
import packetproxy.model.PacketSummarizer
import packetproxy.util.err
import packetproxy.util.errWithStackTrace

class EncoderManager {
  private var isDuplicated = false
  private var moduleList = HashMap<String, Class<out Encoder>>()
  val packetSummarizer =
    object : PacketSummarizer {
      override fun summarizeRequest(encoderName: String?, alpn: String?, packet: Packet): String =
        createSummarizer(encoderName, alpn).getSummarizedRequest(packet)

      override fun summarizeResponse(encoderName: String?, alpn: String?, packet: Packet): String =
        createSummarizer(encoderName, alpn).getSummarizedResponse(packet)
    }

  init {
    try {
      loadModules()
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  private fun createSummarizer(encoderName: String?, alpn: String?): Encoder {
    return try {
      createInstance(encoderName ?: "", alpn)
    } catch (e: Exception) {
      err("エンコードモジュール: %s が見当たらないので、Sample とみなしました", encoderName)
      createInstance("Sample", alpn)
    }
  }

  fun addEncoder(name: String, klass: Class<out Encoder>) {
    moduleList[name] = klass
  }

  fun removeEncoder(name: String) {
    moduleList.remove(name)
  }

  fun hasDuplicateModules(): Boolean = isDuplicated

  fun getEncoderNameList(): Array<String> = moduleList.keys.sorted().toTypedArray()

  @Throws(Exception::class)
  fun createInstance(encoderName: String, alpn: String?): Encoder {
    val encoderClass =
      moduleList[encoderName] ?: throw Exception("Encoder module not found: $encoderName")
    return createInstance(encoderClass, alpn)
  }

  @Throws(Exception::class)
  private fun loadModules() {
    isDuplicated = false
    moduleList = HashMap()
    val compiler = ToolProvider.getSystemJavaCompiler()
    val fileManager =
      compiler.getStandardFileManager(DiagnosticCollector<JavaFileObject>(), null, null)
    for (file in
      fileManager.list(
        StandardLocation.CLASS_PATH,
        ENCODE_PACKAGE,
        setOf(JavaFileObject.Kind.CLASS),
        false,
      )) {
      try {
        val className =
          "$ENCODE_PACKAGE.${Paths.get(file.name).fileName.toString().replace(Regex("\\.class.*$"), "")}"
        val klass = Class.forName(className)
        if (!Encoder::class.java.isAssignableFrom(klass) || Modifier.isAbstract(klass.modifiers))
          continue
        val encoderClass = klass.asSubclass(Encoder::class.java)
        moduleList[createInstance(encoderClass, null).getName()] = encoderClass
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }
    loadModulesFromJar(moduleList)
  }

  @Throws(Exception::class)
  private fun loadModulesFromJar(modules: HashMap<String, Class<out Encoder>>) {
    val files = File(DEFAULT_PLUGIN_DIR).listFiles() ?: return
    for (file in files) {
      if (!file.isFile || FilenameUtils.getExtension(file.getName()) != "jar") continue
      URLClassLoader.newInstance(arrayOf(file.toURI().toURL())).use { classLoader ->
        JarFile(file.getPath()).use { jarFile ->
          for (entry in jarFile.entries().asSequence()) {
            if (entry.isDirectory || !entry.getName().endsWith(".class")) continue
            val klass =
              try {
                classLoader.loadClass(
                  entry.getName().replace(Regex("\\.class.*$"), "").replace("/", ".")
                )
              } catch (exception: Exception) {
                errWithStackTrace(exception)
                continue
              }
            if (
              !Encoder::class.java.isAssignableFrom(klass) || Modifier.isAbstract(klass.modifiers)
            )
              continue
            val encoderClass = klass.asSubclass(Encoder::class.java)
            var encoderName = createInstance(encoderClass, null).getName()
            if (modules.containsKey(encoderName)) {
              isDuplicated = true
              encoderName += "-${file.name}"
            }
            modules[encoderName] = encoderClass
          }
        }
      }
    }
  }

  @Throws(Exception::class)
  private fun createInstance(klass: Class<out Encoder>, alpn: String?): Encoder =
    klass.getConstructor(String::class.java).newInstance(alpn)

  companion object {
    private val DEFAULT_PLUGIN_DIR = "${System.getProperty("user.home")}/.packetproxy/plugins"
    private val ENCODE_PACKAGE = "packetproxy.encode"
  }
}
