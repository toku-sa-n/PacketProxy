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
package packetproxy.model

import com.j256.ormlite.dao.Dao
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import java.io.File
import java.net.URLClassLoader
import java.util.jar.JarFile
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.model.PropertyChangeEventType.EXTENSIONS
import packetproxy.util.errWithStackTrace

class Extensions(private val database: Database) : PropertyChangeListener {
  private val pcs = PropertyChangeSupport(this)
  private var extensionInitializer: ((Extension) -> Unit)? = null

  // Extensionではなく、継承先のインスタンスを保持する必要がある
  // enabledになっている際にのみext_instancesに保持されるようにする
  private var ext_instances: MutableMap<String, Extension> = HashMap()
  // Retain URLClassLoaders for the lifetime of loaded jar extensions.
  private val extensionClassLoaders = ArrayList<URLClassLoader>()
  private var dao: Dao<Extension, String> = database.createTable(Extension::class.java, this)
  private var cache = DaoQueryCache<Extension>()

  init {
    SchemaMigrator.ensureCompatible(database, dao, "extensions") {
      database.dropTable(Extension::class.java)
      dao = database.createTable(Extension::class.java, this)
    }
    ensurePresets()
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    pcs.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    pcs.removePropertyChangeListener(listener)
  }

  fun setExtensionInitializer(initializer: (Extension) -> Unit) {
    extensionInitializer = initializer
    ext_instances.values.forEach(::initializeExtension)
  }

  // return loaded extension or null
  fun loadExtension(name: String, path: String?): Extension? {
    if (presetExtensions.containsKey(name)) {
      var extension: Extension? = null
      try {
        val clazz = presetExtensions[name]!!
        val constructor = clazz.getConstructor()
        extension = constructor.newInstance() as Extension
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
      return extension?.also(::initializeExtension)
    }
    try {
      val filePath = path ?: return null
      val file = File(filePath)
      val urls = arrayOf(file.toURI().toURL())
      val urlClassLoader = URLClassLoader(urls)
      val jar = JarFile(file)
      var extension: Extension? = null
      val entries = jar.entries()
      while (entries.hasMoreElements()) {
        val entry = entries.nextElement()
        val entryName = entry.name
        if (!entryName.endsWith(".class")) continue
        val className = entryName.replace("/", ".").substring(0, entryName.length - 6)
        try {
          val clazz = urlClassLoader.loadClass(className)
          if (!Extension::class.java.isAssignableFrom(clazz)) continue
          val constructor = clazz.getConstructor(String::class.java, String::class.java)
          extension = constructor.newInstance(name, filePath) as Extension
        } catch (e1: ClassNotFoundException) {
          // errWithStackTrace(e1);
        }
      }
      jar.close()
      // Keep URLClassLoader open for the extension lifetime so classes remain resolvable.
      extensionClassLoaders.add(urlClassLoader)
      return extension?.also(::initializeExtension)
    } catch (e: Exception) {
      errWithStackTrace(e)
      return null
    }
  }

  @Throws(Exception::class)
  fun create(ext: Extension) {
    initializeExtension(ext)
    // 存在しないならListに追加
    val name = ext.getName()
    if (name != null && !dao.idExists(name)) {
      dao.create(ext)
      if (ext.isEnabled()) {
        ext_instances[name] = ext
      }
    }
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(id: String) {
    dao.deleteById(id)
    ext_instances.remove(id)
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun delete(ext: Extension) {
    dao.delete(ext)
    ext_instances.remove(ext.getName())
    cache.clear()
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun update(ext: Extension): Extension? {
    var ext = ext
    dao.update(ext)
    val name = ext.getName()
    if (ext.isEnabled() && name != null && !ext_instances.containsKey(name)) {
      val loadedExt = loadExtension(name, ext.getPath())
      if (loadedExt != null) {
        loadedExt.setEnabled(true)
        val loadedName = loadedExt.getName()
        if (loadedName != null) {
          ext_instances[loadedName] = loadedExt
        }
        ext = loadedExt
      }
    } else if (!ext.isEnabled()) {
      // remove because of disabled
      if (name != null) {
        ext_instances.remove(name)
      }
    }
    cache.clear()
    firePropertyChange()
    return ext
  }

  fun refresh() {
    firePropertyChange()
  }

  @Throws(Exception::class)
  fun query(id: String): Extension? {
    val ret = cache.query("query", id)
    if (ret != null) return ret[0]
    var ext: Extension? = null
    if (ext_instances.containsKey(id)) {
      ext = ext_instances[id]
    } else {
      ext = dao.queryForId(id)
      if (ext != null && ext.isEnabled()) {
        // load jar
        val loaded = loadExtension(ext.getName() ?: id, ext.getPath())
        if (loaded != null) {
          loaded.setEnabled(true)
          val loadedName = loaded.getName()
          if (loadedName != null) {
            ext_instances[loadedName] = loaded
          }
          ext = loaded
        }
      }
    }
    if (ext != null) {
      cache.set("query", id, ext)
    }
    return ext
  }

  @Throws(Exception::class)
  fun queryAll(): List<Extension> {
    var ret = cache.query("queryAll", 0)
    if (ret != null) {
      return ret
    }
    ensurePresets()
    ret = dao.queryBuilder().query()
    val newHash = HashMap<String, Extension>()
    for (i in ret.indices) {
      val ext = ret[i]
      if (!ext.isEnabled()) continue
      val name = ext.getName() ?: continue
      if (ext_instances.containsKey(name)) {
        val loadedExt = ext_instances[name] ?: continue
        ret[i] = loadedExt
        newHash[name] = loadedExt
        continue
      }
      val loadedExt = loadExtension(name, ext.getPath())
      if (loadedExt != null) {
        loadedExt.setEnabled(ext.isEnabled())
        ret[i] = loadedExt
        val loadedName = loadedExt.getName()
        if (loadedName != null) {
          newHash[loadedName] = loadedExt
        }
      }
    }
    ext_instances = newHash
    cache.set("queryAll", 0, ret)
    return ret
  }

  fun firePropertyChange() {
    firePropertyChange(null)
  }

  fun firePropertyChange(arg: Any?) {
    pcs.firePropertyChange(EXTENSIONS.toString(), null, arg)
  }

  override fun propertyChange(evt: PropertyChangeEvent) {
    if (!DATABASE_MESSAGE.matches(evt)) {
      return
    }

    val message = evt.newValue as DatabaseMessage
    try {
      when (message) {
        DatabaseMessage.PAUSE,
        DatabaseMessage.RESUME,
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          dao = database.createTable(Extension::class.java, this)
          ext_instances.clear()
          cache.clear()
          ensurePresets()
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(Extension::class.java, this)
          ext_instances.clear()
          cache.clear()
          ensurePresets()
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun ensurePresets() {
    for (clazz in presetExtensions.values) {
      try {
        val extension = clazz.getConstructor().newInstance() as Extension
        val name = extension.getName() ?: continue
        if (!dao.idExists(name)) {
          create(extension)
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  private fun initializeExtension(extension: Extension) {
    extensionInitializer?.invoke(extension)
  }

  companion object {
    private val presetExtensions: MutableMap<String, Class<*>> = HashMap()

    @JvmStatic
    fun registerPreset(clazz: Class<out Extension>) {
      try {
        val extension = clazz.getConstructor().newInstance()
        val name = extension.getName() ?: return
        presetExtensions[name] = clazz
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }
}
