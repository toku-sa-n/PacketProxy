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
import javax.swing.JOptionPane
import packetproxy.extensions.endpointoverview.EndpointOverviewExtension
import packetproxy.extensions.mcp.MCPServerExtension
import packetproxy.extensions.randomness.RandomnessExtension
import packetproxy.extensions.samplehttp.SampleEncoders
import packetproxy.extensions.securityheaders.SecurityHeadersExtension
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.model.PropertyChangeEventType.EXTENSIONS
import packetproxy.util.Logging.errWithStackTrace

class Extensions private constructor() : PropertyChangeListener {
  private val pcs = PropertyChangeSupport(this)

  // Extensionではなく、継承先のインスタンスを保持する必要がある
  // enabledになっている際にのみext_instancesに保持されるようにする
  private var ext_instances: MutableMap<String, Extension> = HashMap()
  private var database: Database = Database.getInstance()
  private var dao: Dao<Extension, String> =
    database.createTable(Extension::class.java, this) as Dao<Extension, String>
  private var cache = DaoQueryCache<Extension>()

  init {
    if (!isLatestVersion()) {
      RecreateTable()
    }

    // load presets
    for (clazz in presetExtensions.values) {
      val constructor = clazz.getConstructor()
      val extension = constructor.newInstance() as Extension
      create(extension)
    }
  }

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    pcs.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    pcs.removePropertyChangeListener(listener)
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
      return extension
    }
    try {
      val file = File(path!!)
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
          extension = constructor.newInstance(name, path) as Extension
        } catch (e1: ClassNotFoundException) {
          // errWithStackTrace(e1);
        }
      }
      jar.close()
      urlClassLoader.close()
      return extension
    } catch (e: Exception) {
      errWithStackTrace(e)
      return null
    }
  }

  @Throws(Exception::class)
  fun create(ext: Extension) {
    // 存在しないならListに追加
    if (!dao.idExists(ext.getName())) {
      dao.create(ext)
      if (ext.isEnabled()) {
        ext_instances[ext.getName()!!] = ext
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
    if (ext.isEnabled() && !ext_instances.containsKey(ext.getName())) {
      val loadedExt = loadExtension(ext.getName()!!, ext.getPath())
      if (loadedExt != null) {
        loadedExt.setEnabled(true)
        ext_instances[loadedExt.getName()!!] = loadedExt
      }
      ext = loadedExt!!
    } else if (!ext.isEnabled()) {
      // remove because of disabled
      ext_instances.remove(ext.getName())
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
      if (ext!!.isEnabled()) {
        // load jar
        ext = loadExtension(ext.getName()!!, ext.getPath())
        if (ext != null) {
          ext.setEnabled(true)
          ext_instances[ext.getName()!!] = ext
        }
      }
    }
    cache.set("query", id, ext!!)
    return ext
  }

  @Throws(Exception::class)
  fun queryAll(): List<Extension> {
    var ret = cache.query("queryAll", 0)
    if (ret != null) {
      return ret
    }
    ret = dao.queryBuilder().query()
    val newHash = HashMap<String, Extension>()
    for (i in ret.indices) {
      val ext = ret[i]
      if (!ext.isEnabled()) continue
      if (ext_instances.containsKey(ext.getName())) {
        val loadedExt = ext_instances[ext.getName()]!!
        ret[i] = loadedExt
        newHash[ext.getName()!!] = loadedExt
        continue
      }
      val loadedExt = loadExtension(ext.getName()!!, ext.getPath())
      if (loadedExt != null) {
        loadedExt.setEnabled(ext.isEnabled())
        ret[i] = loadedExt
        newHash[loadedExt.getName()!!] = loadedExt
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
        DatabaseMessage.PAUSE -> {
          // TODO ロックを取る
        }
        DatabaseMessage.RESUME -> {
          // TODO ロックを取る
        }
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          database = Database.getInstance()
          dao = database.createTable(Extension::class.java, this) as Dao<Extension, String>
          cache.clear()
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          database = Database.getInstance()
          dao = database.createTable(Extension::class.java, this) as Dao<Extension, String>
          cache.clear()
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  @Throws(Exception::class)
  private fun isLatestVersion(): Boolean {
    val result =
      dao.queryRaw("SELECT sql FROM sqlite_master WHERE name='extensions'").firstResult[0]
    return result ==
      "CREATE TABLE `extensions` (`name` VARCHAR , `enabled` BOOLEAN , `path` VARCHAR , PRIMARY KEY (`name`) )"
  }

  @Throws(Exception::class)
  private fun RecreateTable() {
    val option =
      JOptionPane.showConfirmDialog(
        null,
        "Extensionsテーブルの形式が更新されているため\n現在のテーブルを削除して再起動しても良いですか？",
        "テーブルの更新",
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE,
      )
    if (option == JOptionPane.YES_OPTION) {
      database.dropTable(Extension::class.java)
      dao = database.createTable(Extension::class.java, this) as Dao<Extension, String>
    }
  }

  companion object {
    private var instance: Extensions? = null

    private val presetExtensions: MutableMap<String, Class<*>> =
      object : HashMap<String, Class<*>>() {
        init {
          put((MCPServerExtension()).getName()!!, MCPServerExtension::class.java)
          put((RandomnessExtension()).getName()!!, RandomnessExtension::class.java)
          put((SampleEncoders()).getName()!!, SampleEncoders::class.java)
          put((SecurityHeadersExtension()).getName()!!, SecurityHeadersExtension::class.java)
          put((EndpointOverviewExtension()).getName()!!, EndpointOverviewExtension::class.java)
        }
      }

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): Extensions {
      if (instance == null) {
        instance = Extensions()
      }
      return instance!!
    }
  }
}
