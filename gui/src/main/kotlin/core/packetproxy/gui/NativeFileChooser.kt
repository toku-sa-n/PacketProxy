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

import java.awt.Component
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import java.io.FilenameFilter
import javax.swing.JFileChooser
import javax.swing.SwingUtilities
import javax.swing.filechooser.FileNameExtensionFilter
import packetproxy.common.Utils

class NativeFileChooser {
  private data class FilterEntry(val description: String, val extensions: Array<out String>)

  private var selectedFile: File? = null
  private var currentDirectory: File? = null
  private var dialogTitle: String? = null
  private val fileFilters = mutableListOf<FilterEntry>()
  private var acceptAllFileFilterUsed = true

  constructor() {
    currentDirectory = File(System.getProperty("user.home"))
  }

  constructor(currentDirectoryPath: String) {
    currentDirectory = File(currentDirectoryPath)
  }

  fun setCurrentDirectory(dir: File) {
    currentDirectory = dir
  }

  fun setDialogTitle(title: String) {
    dialogTitle = title
  }

  fun setAcceptAllFileFilterUsed(used: Boolean) {
    acceptAllFileFilterUsed = used
  }

  fun addChoosableFileFilter(description: String, vararg extensions: String) {
    fileFilters.add(FilterEntry(description, extensions))
  }

  fun setFileFilter(filter: FileNameExtensionFilter) {
    fileFilters.clear()
    addChoosableFileFilter(filter)
  }

  fun addChoosableFileFilter(filter: FileNameExtensionFilter) {
    fileFilters.add(FilterEntry(filter.description, filter.extensions))
  }

  fun getSelectedFile(): File = requireNotNull(selectedFile)

  fun setSelectedFile(file: File) {
    selectedFile = file
  }

  fun showOpenDialog(parent: Component): Int =
    if (Utils.isMac()) showNativeOpenDialog(parent) else showSwingOpenDialog(parent)

  fun showSaveDialog(parent: Component): Int =
    if (Utils.isMac()) showNativeSaveDialog(parent) else showSwingSaveDialog(parent)

  fun showDirectoryDialog(parent: Component): Int =
    if (Utils.isMac()) showNativeDirectoryDialog(parent) else showSwingDirectoryDialog(parent)

  private fun getFrame(parent: Component?): Frame? =
    when (parent) {
      null -> null
      is Frame -> parent
      else -> SwingUtilities.getAncestorOfClass(Frame::class.java, parent) as? Frame
    }

  private fun createFilenameFilter(): FilenameFilter? {
    if (fileFilters.isEmpty()) return null
    return FilenameFilter { _, name ->
      acceptAllFileFilterUsed ||
        fileFilters.any { entry ->
          entry.extensions.any { extension ->
            name.lowercase().endsWith(".${extension.lowercase()}")
          }
        }
    }
  }

  private fun showNativeOpenDialog(parent: Component): Int =
    runCatching {
        val dialog = FileDialog(getFrame(parent), dialogTitle ?: "Open", FileDialog.LOAD)
        currentDirectory?.let { dialog.directory = it.absolutePath }
        val filter = createFilenameFilter()
        if (filter != null && !acceptAllFileFilterUsed) {
          fileFilters.firstOrNull()?.extensions?.firstOrNull()?.let { dialog.file = "*.$it" }
          dialog.filenameFilter = filter
        }
        dialog.isVisible = true
        val file = dialog.file
        val directory = dialog.directory
        if (file == null || directory == null) return@runCatching CANCEL_OPTION
        val selected = File(directory, file)
        if (filter != null && !filter.accept(File(directory), file))
          return@runCatching CANCEL_OPTION
        selectedFile = selected
        APPROVE_OPTION
      }
      .getOrElse { ERROR_OPTION }

  private fun showNativeSaveDialog(parent: Component): Int =
    runCatching {
        val dialog = FileDialog(getFrame(parent), dialogTitle ?: "Save", FileDialog.SAVE)
        currentDirectory?.let { dialog.directory = it.absolutePath }
        selectedFile?.let { dialog.file = it.name }
        dialog.isVisible = true
        val file = dialog.file
        val directory = dialog.directory
        if (file == null || directory == null) CANCEL_OPTION
        else {
          selectedFile = File(directory, file)
          APPROVE_OPTION
        }
      }
      .getOrElse { ERROR_OPTION }

  private fun showSwingOpenDialog(parent: Component): Int =
    runCatching {
        createSwingChooser().let { chooser ->
          when (chooser.showOpenDialog(parent)) {
            JFileChooser.APPROVE_OPTION -> {
              selectedFile = chooser.selectedFile
              APPROVE_OPTION
            }
            JFileChooser.ERROR_OPTION -> ERROR_OPTION
            else -> CANCEL_OPTION
          }
        }
      }
      .getOrElse { ERROR_OPTION }

  private fun showSwingSaveDialog(parent: Component): Int =
    runCatching {
        createSwingChooser().let { chooser ->
          when (chooser.showSaveDialog(parent)) {
            JFileChooser.APPROVE_OPTION -> {
              selectedFile = chooser.selectedFile
              APPROVE_OPTION
            }
            JFileChooser.ERROR_OPTION -> ERROR_OPTION
            else -> CANCEL_OPTION
          }
        }
      }
      .getOrElse { ERROR_OPTION }

  private fun createSwingChooser() =
    JFileChooser().apply {
      currentDirectory?.let { currentDirectory = it }
      dialogTitle?.let { dialogTitle = it }
      selectedFile?.let { selectedFile = it }
      isAcceptAllFileFilterUsed = acceptAllFileFilterUsed
      fileFilters
        .filter { it.extensions.isNotEmpty() }
        .forEach { addChoosableFileFilter(FileNameExtensionFilter(it.description, *it.extensions)) }
      fileSelectionMode = JFileChooser.FILES_ONLY
    }

  private fun showNativeDirectoryDialog(parent: Component): Int {
    val previous = System.getProperty("apple.awt.fileDialogForDirectories")
    return try {
      System.setProperty("apple.awt.fileDialogForDirectories", "true")
      val dialog = FileDialog(getFrame(parent), dialogTitle ?: "Select folder", FileDialog.LOAD)
      currentDirectory?.let { dialog.directory = it.absolutePath }
      dialog.isVisible = true
      val directory = dialog.directory ?: return CANCEL_OPTION
      selectedFile = dialog.file?.let { File(directory, it) } ?: File(directory)
      APPROVE_OPTION
    } catch (_: Exception) {
      ERROR_OPTION
    } finally {
      if (previous == null) System.clearProperty("apple.awt.fileDialogForDirectories")
      else System.setProperty("apple.awt.fileDialogForDirectories", previous)
    }
  }

  private fun showSwingDirectoryDialog(parent: Component): Int =
    runCatching {
        JFileChooser()
          .apply {
            currentDirectory?.let { currentDirectory = it }
            dialogTitle?.let { dialogTitle = it }
            fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            isAcceptAllFileFilterUsed = true
          }
          .let { chooser ->
            when (chooser.showOpenDialog(parent)) {
              JFileChooser.APPROVE_OPTION -> {
                selectedFile = chooser.selectedFile
                APPROVE_OPTION
              }
              JFileChooser.ERROR_OPTION -> ERROR_OPTION
              else -> CANCEL_OPTION
            }
          }
      }
      .getOrElse { ERROR_OPTION }

  companion object {
    const val APPROVE_OPTION = JFileChooser.APPROVE_OPTION
    const val CANCEL_OPTION = JFileChooser.CANCEL_OPTION
    const val ERROR_OPTION = JFileChooser.ERROR_OPTION
  }
}
