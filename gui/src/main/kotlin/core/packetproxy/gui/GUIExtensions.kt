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
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JTabbedPane
import packetproxy.encode.Encoder
import packetproxy.model.Extension
import packetproxy.util.errWithStackTrace

class GUIExtensions(private val main: GUIMain, private val guiHistory: GUIHistory) {
  private val mainPanel = JPanel()
  private val tabs = JTabbedPane()
  private val extensionMenus = mutableMapOf<String, JMenuItem>()
  private var jarsLoaded = false

  init {
    tabs.addChangeListener {}
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    mainPanel.add(tabs)
  }

  @Throws(Exception::class)
  fun addExtension(extension: Extension) {
    val name = extension.getName()
    if (name != null && tabs.indexOfTab(name) >= 0) return

    (extension as? GuiServiceExtension)?.initialize(main)
    extension.getEncoders().forEach { (encoderName, encoderClass) ->
      if (Encoder::class.java.isAssignableFrom(encoderClass)) {
        main.coreServices.encoderManager.addEncoder(
          encoderName,
          encoderClass.asSubclass(Encoder::class.java),
        )
      }
    }

    extension.createPanel()?.let { tabs.addTab(name, it) }
    extension.historyClickHandler(guiHistory::getPacket)?.let { menuItem ->
      guiHistory.addMenu(menuItem)
      name?.let { extensionMenus[it] = menuItem }
    }
  }

  @Throws(Exception::class)
  fun removeExtension(extension: Extension) {
    extension.getEncoders().forEach { (name, encoderClass) ->
      if (Encoder::class.java.isAssignableFrom(encoderClass)) {
        main.coreServices.encoderManager.removeEncoder(name)
      }
    }
    extension.getName()?.let { name ->
      extensionMenus.remove(name)?.let { guiHistory.removeMenu(it) }
      tabs.indexOfTab(name).takeIf { it >= 0 }?.let { tabs.removeTabAt(it) }
    }
  }

  @Throws(Exception::class)
  fun createPanel(): JComponent {
    if (!jarsLoaded) {
      loadJars()
      jarsLoaded = true
    }
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
              main.modelServices.extensions.create(extension)
            } catch (exception: Exception) {
              errWithStackTrace(exception)
            }
          }
        }
      }
    }
    for (extension in main.modelServices.extensions.queryAll()) {
      if (extension.isEnabled()) addExtension(extension)
    }
  }
}
