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
package packetproxy.gui

import java.io.File
import java.net.URLClassLoader
import java.util.jar.JarFile
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JFrame
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JTabbedPane
import packetproxy.EncoderManager
import packetproxy.encode.Encoder
import packetproxy.model.Extension
import packetproxy.model.Extensions
import packetproxy.util.Logging.errWithStackTrace

class GUIExtensions private constructor() {
  private val mainPanel = JPanel()
  private val tabs = JTabbedPane()
  private val extensionMenus = mutableMapOf<String, JMenuItem>()

  init {
    tabs.addChangeListener {}
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    mainPanel.add(tabs)
  }

  @Throws(Exception::class)
  fun addExtension(extension: Extension) {
    extension.getEncoders().forEach { (name, encoderClass) ->
      if (Encoder::class.java.isAssignableFrom(encoderClass)) {
        EncoderManager.getInstance().addEncoder(name, encoderClass.asSubclass(Encoder::class.java))
      }
    }

    extension.createPanel()?.let { tabs.addTab(extension.getName(), it) }
    extension.historyClickHandler()?.let {
      GUIHistory.getInstance().addMenu(it)
      extension.getName()?.let { name -> extensionMenus[name] = it }
    }
  }

  @Throws(Exception::class)
  fun removeExtension(extension: Extension) {
    extension.getEncoders().forEach { (name, encoderClass) ->
      if (Encoder::class.java.isAssignableFrom(encoderClass)) {
        EncoderManager.getInstance().removeEncoder(name)
      }
    }
    extension.getName()?.let { name ->
      extensionMenus.remove(name)?.let { GUIHistory.getInstance().removeMenu(it) }
      tabs.indexOfTab(name).takeIf { it >= 0 }?.let { tabs.removeTabAt(it) }
    }
  }

  @Throws(Exception::class)
  fun createPanel(): JComponent {
    loadJars()
    return mainPanel
  }

  @Throws(Exception::class)
  private fun loadJars() {
    val directory = File("${System.getProperty("user.home")}/.packetproxy/extensions")
    if (!directory.exists()) directory.mkdirs()
    val jarFiles = directory.listFiles { _, name -> name.endsWith(".jar") } ?: emptyArray()
    URLClassLoader(jarFiles.map { it.toURI().toURL() }.toTypedArray()).use { classLoader ->
      for (jarFile in jarFiles) {
        JarFile(jarFile).use { jar ->
          val entries = jar.entries()
          while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            if (!entry.name.endsWith(".class")) continue
            val className = entry.name.replace("/", ".").removeSuffix(".class")
            try {
              val extensionClass = classLoader.loadClass(className)
              if (!Extension::class.java.isAssignableFrom(extensionClass)) continue
              val extension = extensionClass.getConstructor().newInstance() as Extension
              if (extension.getName() == null) extension.setName(className)
              if (extension.getPath() == null) extension.setPath(jarFile.toPath().toString())
              Extensions.getInstance().create(extension)
            } catch (exception: Exception) {
              errWithStackTrace(exception)
            }
          }
        }
      }
    }
    for (extension in Extensions.getInstance().queryAll()) {
      if (extension.isEnabled()) addExtension(extension)
    }
  }

  companion object {
    private var instance: GUIExtensions? = null
    private var owner: JFrame? = null

    @JvmStatic fun getOwner(): JFrame = requireNotNull(owner)

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): GUIExtensions {
      if (instance == null) instance = GUIExtensions()
      return instance!!
    }
  }
}
