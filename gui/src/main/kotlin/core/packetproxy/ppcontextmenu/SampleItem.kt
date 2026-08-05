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
package packetproxy.ppcontextmenu

import java.io.File
import javax.swing.JFrame
import javax.swing.JOptionPane
import org.apache.commons.io.FileUtils
import packetproxy.common.i18nString
import packetproxy.gui.GUIPacket
import packetproxy.gui.NativeFileChooser

class SampleItem : PPContextMenu() {
  override fun getLabelName(): String = "sample implementation"

  @Throws(Exception::class)
  override fun action() {
    val saveFile = NativeFileChooser()
    saveFile.setAcceptAllFileFilterUsed(false)
    saveFile.addChoosableFileFilter(i18nString("Data file (.dat)"), "dat")
    val mainFrame = this.dependentData!!.get("main_frame") as JFrame
    val selected = saveFile.showSaveDialog(mainFrame)
    if (selected != NativeFileChooser.APPROVE_OPTION) return
    val file: File = saveFile.getSelectedFile()
    val guiPacket = this.dependentData!!.get("gui_packet") as GUIPacket
    val data = guiPacket.getPacket().getReceivedData()
    FileUtils.writeByteArrayToFile(file, data)
    JOptionPane.showMessageDialog(mainFrame, i18nString("Saved to %s!", file.path))
  }
}
