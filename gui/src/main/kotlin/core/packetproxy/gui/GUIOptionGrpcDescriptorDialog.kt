/*
 * Copyright 2026 DeNA Co., Ltd.
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

import java.awt.BorderLayout
import java.awt.Dimension
import java.io.File
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.SwingUtilities
import javax.swing.SwingWorker
import javax.swing.filechooser.FileNameExtensionFilter
import javax.swing.table.DefaultTableModel
import packetproxy.common.*
import packetproxy.grpc.GrpcServiceRegistryStore
import packetproxy.grpc.ProtoFileSet
import packetproxy.grpc.ProtocRunner
import packetproxy.model.ModelServices

data class GrpcDescriptorDialogOutcome(
  @get:JvmName("isApplied") val applied: Boolean,
  val descriptorPath: String?,
)

/**
 * Single dialog for .desc management: browse existing .desc, compile from .proto, inspect services.
 * Replaces the previous two-dialog (GrpcDescriptorDialog → ProtoCompileDialog) flow.
 */
class GUIOptionGrpcDescriptorDialog(
  private val frameOwner: JFrame?,
  private val serverId: Int?,
  initialPath: String?,
  private val modelServices: ModelServices,
) : JDialog(frameOwner, i18nString("gRPC descriptor"), true) {
  private val registryStore =
    GrpcServiceRegistryStore(
      modelServices.database,
      modelServices.servers,
      modelServices.listenPorts,
    )

  private var workingPath: String? = initialPath?.trim()?.takeIf { it.isNotEmpty() }
  private var outcome = GrpcDescriptorDialogOutcome(false, null)

  private val pathLabel = JLabel()
  private val protoSet = ProtoFileSet()
  private val protoTableModel =
    object : DefaultTableModel(i18nStringArray("Path"), 0) {
      override fun isCellEditable(row: Int, column: Int) = false
    }
  private val serviceTableModel =
    object : DefaultTableModel(i18nStringArray("Service", "Method"), 0) {
      override fun isCellEditable(row: Int, column: Int) = false
    }
  private val protoTable = JTable(protoTableModel)

  init {
    val root = JPanel(BorderLayout(8, 8))
    root.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

    pathLabel.border = BorderFactory.createEmptyBorder(0, 0, 8, 0)
    updatePathLabel()
    root.add(pathLabel, BorderLayout.NORTH)

    val center = JPanel()
    center.layout = BoxLayout(center, BoxLayout.Y_AXIS)

    // --- .proto file section ---
    val protoPanel = JPanel(BorderLayout(4, 4))
    protoPanel.border = BorderFactory.createTitledBorder(i18nString(".proto files"))

    val protoButtons = JPanel()
    protoButtons.layout = BoxLayout(protoButtons, BoxLayout.X_AXIS)
    val addFile = JButton(i18nString("Add .proto file..."))
    addFile.addActionListener { addProtoFiles() }
    val addDir = JButton(i18nString("Add directory..."))
    addDir.addActionListener { addProtoDirectory() }
    val removeProto = JButton(i18nString("Remove item"))
    removeProto.addActionListener { removeSelectedProto() }
    protoButtons.add(addFile)
    protoButtons.add(addDir)
    protoButtons.add(removeProto)
    protoPanel.add(protoButtons, BorderLayout.NORTH)

    protoTable.preferredScrollableViewportSize = Dimension(520, 100)
    protoPanel.add(JScrollPane(protoTable), BorderLayout.CENTER)
    center.add(protoPanel)

    // --- Action buttons ---
    val actionRow = JPanel(java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0))
    val generate = JButton(i18nString("Generate .desc"))
    generate.addActionListener { runGenerate() }
    val browse = JButton(i18nString("Browse .desc..."))
    browse.addActionListener { browseDescFile() }
    val remove = JButton(i18nString("Unregister"))
    remove.addActionListener { removeDescriptor() }
    actionRow.add(generate)
    actionRow.add(browse)
    actionRow.add(remove)
    center.add(actionRow)

    // --- Service / method table ---
    val serviceTable = JTable(serviceTableModel)
    serviceTable.preferredScrollableViewportSize = Dimension(520, 160)
    val serviceScroll = JScrollPane(serviceTable)
    serviceScroll.border = BorderFactory.createTitledBorder(i18nString("Services / methods"))
    center.add(serviceScroll)

    root.add(center, BorderLayout.CENTER)

    // --- Footer ---
    val footer = JPanel()
    footer.layout = BoxLayout(footer, BoxLayout.X_AXIS)
    val ok = JButton(i18nString("OK"))
    ok.addActionListener {
      val p = workingPath?.trim()?.takeIf { it.isNotEmpty() }
      outcome = GrpcDescriptorDialogOutcome(true, p)
      dispose()
    }
    val cancel = JButton(i18nString("Cancel"))
    cancel.addActionListener {
      outcome = GrpcDescriptorDialogOutcome(false, null)
      dispose()
    }
    footer.add(ok)
    footer.add(cancel)
    root.add(footer, BorderLayout.SOUTH)

    contentPane = root
    pack()
    setLocationRelativeTo(frameOwner)
    refreshServiceList()
  }

  private fun updatePathLabel() {
    val p = workingPath?.trim()?.takeIf { it.isNotEmpty() }
    pathLabel.text =
      if (p == null) {
        i18nString("No descriptor loaded")
      } else {
        "<html><b>${i18nString("Current .desc:")}</b><br/>${escapeHtml(p)}</html>"
      }
  }

  private fun escapeHtml(s: String): String =
    s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

  // --- .proto management ---

  private fun addProtoFiles() {
    try {
      val chooser = NativeFileChooser()
      chooser.setDialogTitle(i18nString("Select .proto files"))
      chooser.addChoosableFileFilter(FileNameExtensionFilter("Protocol Buffers (*.proto)", "proto"))
      chooser.setAcceptAllFileFilterUsed(false)
      if (chooser.showOpenDialog(this) == NativeFileChooser.APPROVE_OPTION) {
        val f = chooser.getSelectedFile()
        if (f != null && protoSet.addFile(f)) {
          protoTableModel.addRow(arrayOf(f.absolutePath))
        }
      }
    } catch (ex: Exception) {
      JOptionPane.showMessageDialog(
        this,
        ex.message,
        i18nString("Error"),
        JOptionPane.ERROR_MESSAGE,
      )
    }
  }

  private fun addProtoDirectory() {
    try {
      val chooser = NativeFileChooser()
      chooser.setDialogTitle(i18nString("Select directory"))
      if (chooser.showDirectoryDialog(this) == NativeFileChooser.APPROVE_OPTION) {
        val dir = chooser.getSelectedFile()
        if (dir != null && dir.isDirectory) {
          val n = protoSet.addDirectoryShallow(dir)
          if (n == 0) {
            JOptionPane.showMessageDialog(
              this,
              i18nString("No .proto files found in the selected directory."),
              i18nString("Info"),
              JOptionPane.INFORMATION_MESSAGE,
            )
          } else {
            protoTableModel.rowCount = 0
            for (f in protoSet.list()) {
              protoTableModel.addRow(arrayOf(f.absolutePath))
            }
          }
        }
      }
    } catch (ex: Exception) {
      JOptionPane.showMessageDialog(
        this,
        ex.message,
        i18nString("Error"),
        JOptionPane.ERROR_MESSAGE,
      )
    }
  }

  private fun removeSelectedProto() {
    val row = protoTable.selectedRow
    if (row >= 0) {
      try {
        val f = File(protoTableModel.getValueAt(row, 0) as String)
        protoSet.remove(f)
        protoTableModel.removeRow(row)
      } catch (ex: Exception) {
        JOptionPane.showMessageDialog(
          this,
          ex.message,
          i18nString("Error"),
          JOptionPane.ERROR_MESSAGE,
        )
      }
    }
  }

  // --- .desc generation & selection ---

  private fun runGenerate() {
    val protos = protoSet.list()
    if (protos.isEmpty()) {
      JOptionPane.showMessageDialog(
        this,
        i18nString("Add at least one .proto file."),
        i18nString("Error"),
        JOptionPane.WARNING_MESSAGE,
      )
      return
    }
    val dialog = this
    val worker =
      object : SwingWorker<Void?, Void?>() {
        @Throws(Exception::class)
        override fun doInBackground(): Void? {
          ProtocRunner.checkProtocOnPath()
          val includes = protoSet.includePaths()
          val r = ProtocRunner.run(modelServices.database, protos, includes, serverId)
          if (!r.ok) {
            throw Exception(if (r.stderr.isEmpty()) "exit ${r.exitCode}" else r.stderr)
          }
          workingPath = r.descFile.absolutePath
          return null
        }

        override fun done() {
          try {
            get()
            SwingUtilities.invokeLater {
              updatePathLabel()
              refreshServiceList()
            }
          } catch (e: Exception) {
            val c = e.cause ?: e
            JOptionPane.showMessageDialog(
              dialog,
              c.message,
              i18nString("protoc failed"),
              JOptionPane.ERROR_MESSAGE,
            )
          }
        }
      }
    worker.execute()
  }

  private fun browseDescFile() {
    try {
      val chooser = NativeFileChooser()
      chooser.setDialogTitle(i18nString("Select descriptor file"))
      workingPath
        ?.let { File(it).parentFile }
        ?.takeIf { it.isDirectory }
        ?.let { chooser.setCurrentDirectory(it) }
      chooser.addChoosableFileFilter(FileNameExtensionFilter("Descriptor set (*.desc)", "desc"))
      chooser.setAcceptAllFileFilterUsed(true)
      if (chooser.showOpenDialog(this) == NativeFileChooser.APPROVE_OPTION) {
        val f = chooser.getSelectedFile()
        if (f != null && f.isFile) {
          workingPath = f.absolutePath
          updatePathLabel()
          refreshServiceList()
        }
      }
    } catch (ex: Exception) {
      JOptionPane.showMessageDialog(
        this,
        ex.message,
        i18nString("Error"),
        JOptionPane.ERROR_MESSAGE,
      )
    }
  }

  /** Clears the selected path for this server; does not delete the `.desc` file on disk. */
  private fun removeDescriptor() {
    val prev = workingPath?.trim()?.takeIf { it.isNotEmpty() }
    if (prev != null) {
      try {
        registryStore.invalidate(File(prev))
      } catch (_: Exception) {}
    }
    workingPath = null
    updatePathLabel()
    serviceTableModel.rowCount = 0
  }

  private fun refreshServiceList() {
    serviceTableModel.rowCount = 0
    val p = workingPath?.trim()?.takeIf { it.isNotEmpty() } ?: return
    try {
      val f = File(p)
      if (!f.isFile) {
        try {
          registryStore.invalidate(f)
        } catch (_: Exception) {}
        JOptionPane.showMessageDialog(
          this,
          i18nString("Descriptor file does not exist."),
          i18nString("Error"),
          JOptionPane.WARNING_MESSAGE,
        )
        return
      }
      // Drop in-memory parse so this dialog and encoders re-read the file from disk (same path may
      // have
      // been replaced outside PacketProxy, e.g. another protoc run).
      registryStore.invalidate(f)
      val registry = registryStore.get(f)
      for ((service, method) in registry.getServiceMethodEntries()) {
        serviceTableModel.addRow(arrayOf(service, method))
      }
    } catch (ex: Exception) {
      JOptionPane.showMessageDialog(
        this,
        ex.message,
        i18nString("Error"),
        JOptionPane.ERROR_MESSAGE,
      )
    }
  }

  fun showManageDialog(): GrpcDescriptorDialogOutcome {
    isVisible = true
    return outcome
  }
}
