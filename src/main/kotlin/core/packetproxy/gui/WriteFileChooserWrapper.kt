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
import java.util.EventListener
import javax.swing.JFrame
import javax.swing.JOptionPane

class WriteFileChooserWrapper {
  private lateinit var fileChooser: NativeFileChooser
  private lateinit var owner: JFrame
  private lateinit var fileExtension: String
  private var listener: FileChooserListener? = null

  constructor(owner: JFrame, fileExtension: String) {
    setFileChooser(owner, fileExtension, System.getProperty("user.home"))
  }

  constructor(owner: JFrame, fileExtension: String, currentDirectory: String) {
    setFileChooser(owner, fileExtension, currentDirectory)
  }

  fun showSaveDialog() {
    when (fileChooser.showSaveDialog(owner)) {
      NativeFileChooser.APPROVE_OPTION -> approveSelection()
      NativeFileChooser.CANCEL_OPTION -> listener?.onCanceled()
      NativeFileChooser.ERROR_OPTION -> listener?.onError()
    }
  }

  fun addFileChooserListener(listener: FileChooserListener): Int {
    if (this.listener != null) {
      return EVENTLISTENER_IS_ALREADY_EXISTS
    }
    this.listener = listener
    return EVENTLISTENER_IS_ADDED
  }

  private fun approveSelection() {
    var selectedFile = fileChooser.getSelectedFile() ?: return
    var filePath =
      if (selectedFile.name.matches(".+\\.$fileExtension".toRegex())) {
        selectedFile.absolutePath
      } else {
        "${selectedFile.absolutePath}.$fileExtension"
      }
    var finalFile = File(filePath)
    if (finalFile.exists()) {
      when (
        JOptionPane.showConfirmDialog(
          owner,
          "ファイルが既に存在しますが上書きしますか？",
          "Existing file",
          JOptionPane.YES_NO_CANCEL_OPTION,
        )
      ) {
        JOptionPane.YES_OPTION -> listener?.onApproved(finalFile, fileExtension)
        JOptionPane.NO_OPTION,
        JOptionPane.CLOSED_OPTION -> return
        JOptionPane.CANCEL_OPTION -> listener?.onCanceled()
      }
      return
    }
    listener?.onApproved(finalFile, fileExtension)
  }

  private fun setFileChooser(owner: JFrame, fileExtension: String, currentDirectory: String) {
    this.owner = owner
    this.fileExtension = fileExtension
    fileChooser = NativeFileChooser(currentDirectory)
    fileChooser.addChoosableFileFilter("*.$fileExtension", fileExtension)
    fileChooser.setAcceptAllFileFilterUsed(false)
  }

  interface FileChooserListener : EventListener {
    fun onApproved(file: File, extension: String)

    fun onCanceled()

    fun onError()
  }

  private companion object {
    const val EVENTLISTENER_IS_ALREADY_EXISTS = -1
    const val EVENTLISTENER_IS_ADDED = -1
  }
}
