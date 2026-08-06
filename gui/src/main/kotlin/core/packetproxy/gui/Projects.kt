/*
 * Copyright 2025 DeNA Co., Ltd.
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

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.text.SimpleDateFormat
import java.util.Date
import org.apache.commons.io.FilenameUtils
import packetproxy.common.*
import packetproxy.common.RecentProjectsStore
import packetproxy.model.Database

class Projects(
  private val database: Database,
  private val recentProjectsStore: RecentProjectsStore,
) {
  class ProjectInfo(private val path: String) {
    private val name: String
    private val lastModified: String
    private val lastModifiedMillis: Long

    init {
      var projectPath = Paths.get(path)
      name = extractProjectName(projectPath)
      lastModifiedMillis = getLastModifiedMillis(projectPath)
      lastModified = formatLastModified(projectPath)
    }

    fun getPath(): String = path

    fun getName(): String = name

    fun getLastModified(): String = lastModified

    fun getLastModifiedMillis(): Long = lastModifiedMillis

    override fun toString(): String = name

    private fun extractProjectName(path: Path): String =
      FilenameUtils.removeExtension(path.fileName.toString())

    private fun getLastModifiedMillis(path: Path): Long {
      return try {
        Files.getLastModifiedTime(path).toMillis()
      } catch (exception: Exception) {
        0L
      }
    }

    private fun formatLastModified(path: Path): String {
      return try {
        var fileTime = Files.getLastModifiedTime(path)
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date(fileTime.toMillis()))
      } catch (exception: Exception) {
        i18nString("Unknown")
      }
    }
  }

  @Throws(Exception::class)
  fun getValidRecentProjects(): List<ProjectInfo> {
    var recents = ArrayList(recentProjectsStore.load())
    var validRecents = ArrayList<ProjectInfo>()
    var validPaths = ArrayList<String>()
    for (path in recents) {
      if (!Files.exists(Paths.get(path))) {
        continue
      }
      validRecents.add(ProjectInfo(path))
      validPaths.add(path)
    }
    if (validPaths.size != recents.size) {
      recentProjectsStore.save(validPaths)
    }
    validRecents.sortByDescending { it.getLastModifiedMillis() }
    return validRecents
  }

  @Throws(Exception::class)
  fun openProject(path: String) {
    database.openAt(path)
    recentProjectsStore.add(Paths.get(path))
  }

  @Throws(Exception::class)
  fun createTemporaryProject(): String {
    var temporaryDirectory = Paths.get(System.getProperty("java.io.tmpdir"))
    Files.createDirectories(temporaryDirectory)
    var timestamp = SimpleDateFormat("yyyyMMdd-HHmmss").format(Date())
    var database = temporaryDirectory.resolve("packetproxy-$timestamp.sqlite3")
    this.database.openAt(database.toString())
    return database.toString()
  }

  @Throws(Exception::class)
  fun createNewProject(name: String): String {
    val sanitized = sanitizeProjectName(name)
    var projectDirectory = Paths.get(System.getProperty("user.home"), ".packetproxy", "projects")
    Files.createDirectories(projectDirectory)
    var database = projectDirectory.resolve("$sanitized.sqlite3").normalize()
    if (!database.startsWith(projectDirectory.normalize())) {
      throw IllegalArgumentException("Invalid project name")
    }
    this.database.openAt(database.toString())
    recentProjectsStore.add(database)
    return database.toString()
  }

  companion object {
    fun sanitizeProjectName(name: String): String {
      val trimmed = name.trim()
      require(trimmed.isNotEmpty()) { "Project name cannot be empty" }
      require(!trimmed.contains("..")) { "Project name must not contain path traversal" }
      require(!trimmed.contains('/') && !trimmed.contains('\\')) {
        "Project name must not contain path separators"
      }
      require(trimmed.matches(Regex("^[\\w.\\- ]+$"))) {
        "Project name contains invalid characters"
      }
      return trimmed
    }
  }
}
