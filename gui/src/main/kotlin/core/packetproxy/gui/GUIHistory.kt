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

import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.Toolkit
import java.awt.event.ComponentAdapter
import java.awt.event.ComponentEvent
import java.awt.event.FocusAdapter
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.io.File
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.Hashtable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.AbstractButton
import javax.swing.BoxLayout
import javax.swing.ImageIcon
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JToggleButton
import javax.swing.SwingConstants
import javax.swing.SwingUtilities
import javax.swing.SwingWorker
import javax.swing.event.ListSelectionEvent
import javax.swing.event.TableModelEvent
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.DefaultTableModel
import javax.swing.table.TableCellRenderer
import javax.swing.table.TableRowSorter
import packetproxy.common.*
import packetproxy.common.Utils
import packetproxy.model.Database.DatabaseMessage
import packetproxy.model.OptionTableModel
import packetproxy.model.Packet
import packetproxy.model.PacketSummarizer
import packetproxy.model.PropertyChangeEventType.DATABASE_MESSAGE
import packetproxy.model.PropertyChangeEventType.FILTERS
import packetproxy.model.PropertyChangeEventType.PACKETS
import packetproxy.util.errWithStackTrace

class GUIHistory(private val main: GUIMain, restore: Boolean) : PropertyChangeListener {
  private val owner = main
  private val packetSummarizer: PacketSummarizer = main.coreServices.encoderManager.packetSummarizer
  private val columnNames =
    i18nStringArray(
      "#",
      "Request",
      "Status",
      "Length",
      "Client IP",
      "Client Port",
      "Server IP",
      "Server Port",
      "Time",
      "Resend",
      "Modified",
      "Type",
      "Encode",
      "ALPN",
      "Group",
    )
  private val columnWidth =
    intArrayOf(50, 420, 70, 70, 100, 55, 100, 55, 110, 45, 45, 90, 80, 45, 45)
  private lateinit var splitPanel: JSplitPane
  private lateinit var mainPanel: JPanel
  private lateinit var tableModel: OptionTableModel
  private val colorManager = TableCustomColorManager()
  private lateinit var table: JTable
  private val packets = main.modelServices.packets
  private val guiPacket = GUIPacket(main)

  fun getGuiPacket(): GUIPacket = guiPacket

  fun getPacket(): Packet = guiPacket.getPacket()

  lateinit var sorter: TableRowSorter<OptionTableModel>
  private lateinit var guiFilter: HintTextField
  private var preferredPosition = 0
  private val historyUpdateService = Executors.newSingleThreadExecutor()
  private val updatePacketIds = HashSet<Int>()
  // Int値のPACKETSプロパティ変更(packet id)をEDT上で1回のinvokeLaterにまとめてドレインする。
  // 未処理の create(-id) は update(+id) で潰さない（レスポンス単独行化を防ぐ）。
  private val packetNotificationCoalescer = PacketHistoryNotificationCoalescer()
  private val intPacketUpdateScheduled = AtomicBoolean(false)
  private val idRow = Hashtable<Int, Int>()
  private var dialogOnce = false
  private val autoScroll = GUIHistoryAutoScroll()
  private lateinit var menu: JPopupMenu
  private val pairingService = PacketPairingService()

  private val packetColorGreen = Color(0x7F, 0xFF, 0xD4)
  private val packetColorBrown = Color(0xD2, 0x69, 0x1E)
  private val packetColorYellow = Color(0xFF, 0xD7, 0x00)

  init {
    packets.addPropertyChangeListener(this)
    main.modelServices.resenderPackets.initTable(restore)
    main.modelServices.filters.addPropertyChangeListener(this)
  }

  fun getTableModel(): DefaultTableModel = tableModel

  fun filter() {
    if (!sortByText(guiFilter.text)) {
      return
    }
    for (i in 0 until table.rowCount) {
      val id = table.getValueAt(i, COL_ID) as Int
      if (id == preferredPosition) {
        table.changeSelection(i, 0, false, false)
        val rowsVisible = table.parent.height / table.rowHeight / 2
        val cellRect = table.getCellRect(i + rowsVisible, 0, true)
        table.scrollRectToVisible(cellRect)
      }
    }
  }

  fun createPanel(): JComponent {
    tableModel =
      object : OptionTableModel(columnNames, 0) {
        override fun isCellEditable(row: Int, column: Int): Boolean = false
      }
    tableModel.addTableModelListener { event: TableModelEvent ->
      if (event.type == TableModelEvent.INSERT) {
        // Nothing to do
      }
    }
    table =
      object : JTable(tableModel) {
        override fun prepareRenderer(
          renderer: TableCellRenderer,
          row: Int,
          column: Int,
        ): Component {
          val component = super.prepareRenderer(renderer, row, column)
          try {
            val selected = isRowSelected(row)
            val firstSelected = selected && this.selectedRow == row
            val packetId = getValueAt(row, COL_ID) as Int
            val modified = getValueAt(row, COL_MODIFIED) as Boolean
            val resend = getValueAt(row, COL_RESEND) as Boolean
            when {
              selected && firstSelected -> {
                component.foreground = Color.WHITE
                component.background = Color(0x5B, 0x7C, 0xFF)
              }
              selected -> {
                component.foreground = Color.WHITE
                component.background = Color(0x9A, 0xB0, 0xFF)
              }
              colorManager.contains(packetId) -> {
                component.foreground = Color.BLACK
                component.background = colorManager.getColor(packetId)
              }
              resend -> {
                component.foreground = Color.BLACK
                component.background = Color(0xB8, 0xD9, 0xF0)
              }
              modified -> {
                component.foreground = Color.BLACK
                component.background = Color(0xF0, 0xC8, 0xD0)
              }
              else -> {
                component.foreground = Color.BLACK
                component.background = if (row % 2 == 0) Color.WHITE else Color(0xF0, 0xF0, 0xF0)
              }
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
          return component
        }
      }
    table.rowHeight = main.modelServices.fontManager.getUIFontHeight(table)
    table.autoResizeMode = JTable.AUTO_RESIZE_OFF
    for (i in columnNames.indices) {
      table.getColumn(columnNames[i]).preferredWidth = columnWidth[i]
    }
    applyNumericColumnAlignment()
    apply(table, columnNames.size)
    (table.getDefaultRenderer(Boolean::class.javaObjectType) as JComponent).isOpaque = true
    table.selectionModel.addListSelectionListener { e: ListSelectionEvent ->
      if (e.valueIsAdjusting) return@addListSelectionListener
      try {
        preferredPosition = selectedPacketId
        if (preferredPosition <= 0) return@addListSelectionListener
        val packetId = preferredPosition
        historyUpdateService.submit {
          val packet = packets.query(packetId) ?: return@submit
          SwingUtilities.invokeLater {
            try {
              resolveAndShowPacket(packet, false)
            } catch (exception: Exception) {
              errWithStackTrace(exception)
            }
          }
        }
      } catch (_: Exception) {
        // Nothing to do
      }
    }
    sorter = TableRowSorter(tableModel)
    sorter.sortsOnUpdates = false
    sorter.toggleSortOrder(14)
    table.rowSorter = sorter

    val handles =
      GUIHistoryContextMenuFactory()
        .build(
          this,
          owner,
          table,
          guiPacket,
          packets,
          colorManager,
          packetColorGreen,
          packetColorBrown,
          packetColorYellow,
        )
    menu = handles.menu
    addKeyboardNavigation(handles.send, handles.sendToResender, handles.copy, handles.copyAll)
    addTableMouseListeners()
    addTableResizeListener()

    val scrollPane = JScrollPane(table)
    scrollPane.verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_ALWAYS
    scrollPane.setCorner(JScrollPane.UPPER_RIGHT_CORNER, autoScroll)
    splitPanel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
    splitPanel.add(scrollPane)
    splitPanel.add(guiPacket.createPanel())
    splitPanel.dividerLocation = 300
    splitPanel.resizeWeight = 0.35
    splitPanel.alignmentX = Component.CENTER_ALIGNMENT

    mainPanel = JPanel()
    mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)
    mainPanel.add(createFilterPanel())
    mainPanel.add(splitPanel)
    return mainPanel
  }

  fun searchFromRequest(searchWord: String): List<Int> {
    val ids = ArrayList<Int>()
    for (i in 0 until table.rowCount) {
      val request = tableModel.getValueAt(i, 1) as String
      if (request.matches(String.format(".*%s.*", searchWord).toRegex())) {
        ids.add(i)
      }
    }
    return ids
  }

  val selectedPacketId: Int
    get() {
      val index = table.selectedRow
      if (index < 0 || index >= table.rowCount) {
        return 0
      }
      return table.getValueAt(index, COL_ID) as Int
    }

  override fun propertyChange(event: PropertyChangeEvent) {
    when {
      PACKETS.matches(event) -> handlePacketsPropertyChange(event)
      FILTERS.matches(event) -> handleFiltersPropertyChange(event)
      DATABASE_MESSAGE.matches(event) -> handleDatabaseMessagePropertyChange(event)
    }
  }

  fun updateRequestOne(id: Int) {
    synchronized(updatePacketIds) { updatePacketIds.add(id) }
    updateRequest(false)
  }

  fun updateAll() {
    val packetList = packets.queryAllMetadata()
    tableModel.rowCount = 0
    idRow.clear()
    pairingService.clear()
    for (packet in packetList) {
      val groupId = packet.getGroup()
      val isResponse = packet.getDirection() == Packet.Direction.SERVER
      val packetCount = countAndTrackPacket(packet)
      if (shouldUnmergeExisting(packetCount, groupId)) {
        unmergeExistingPairing(groupId)
      }
      if (shouldMergeResponse(groupId, isResponse)) {
        mergeResponseIntoRequestRow(packet, groupId, packet.getId(), false)
      } else {
        addNewRowWithGroupTracking(packet, packet.getId(), isResponse, groupId)
      }
    }
    updatePacketIds.clear()
  }

  fun updateAllAsync() {
    Thread {
        try {
          rebuildAsyncSkeleton()
          fillAsyncRowsFromMetadata()
        } catch (exception: Exception) {
          errWithStackTrace(exception)
        }
      }
      .start()
  }

  /** スケルトン構築をバックグラウンドで進め、テーブル操作だけ EDT に載せる。 */
  private fun rebuildAsyncSkeleton() {
    SwingUtilities.invokeAndWait {
      tableModel.rowCount = 0
      colorManager.clear()
      idRow.clear()
      pairingService.clear()
      updatePacketIds.clear()
    }
    packets.forEachMetadataPage(SKELETON_PAGE_SIZE) { page ->
      SwingUtilities.invokeAndWait {
        for (packet in page) {
          val id = packet.getId()
          val color = packet.getColor()
          val groupId = packet.getGroup()
          val isResponse = packet.getDirection() == Packet.Direction.SERVER
          val packetCount = countAndTrackPacket(packet)
          if (shouldUnmergeExisting(packetCount, groupId)) {
            unmergeExistingPairingInAsyncModel(groupId)
          }
          if (shouldMergeResponse(groupId, isResponse)) {
            mergeResponseMappingOnly(id, groupId)
          } else {
            addNewAsyncPlaceholderRowWithGroupTracking(id, isResponse, groupId)
          }
          when (color) {
            "green" -> colorManager.add(id, packetColorGreen)
            "brown" -> colorManager.add(id, packetColorBrown)
            "yellow" -> colorManager.add(id, packetColorYellow)
          }
        }
      }
    }
  }

  /** メタデータで埋め、永続要約が空の行だけ BLOB を読んで backfill する。新しい行から順に UI を更新する。 */
  private fun fillAsyncRowsFromMetadata() {
    var limit = FILL_PAGE_SIZE
    var index = packets.countOf()
    while (index > 0) {
      try {
        val offset =
          if (index - limit < 0) {
            limit = index
            0L
          } else {
            index - limit
          }
        val range = packets.queryPageMetadata(offset, limit, true)
        val packetsForUpdate = range.map { meta -> resolvePacketForAsyncFill(meta) }.filterNotNull()
        SwingUtilities.invokeLater {
          try {
            for (packet in packetsForUpdate) {
              updateOne(packet)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
        index -= limit
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }
  }

  private fun resolvePacketForAsyncFill(meta: Packet): Packet? {
    if (!needsPersistedSummaryBackfill(meta)) {
      return meta
    }
    return try {
      val full = packets.query(meta.getId()) ?: return meta
      backfillPersistedSummariesIfNeeded(full)
      full
    } catch (exception: Exception) {
      errWithStackTrace(exception)
      meta
    }
  }

  private fun needsPersistedSummaryBackfill(packet: Packet): Boolean {
    val needsRequest =
      packet.getDirection() == Packet.Direction.CLIENT &&
        packet.getSummarizedRequestColumn().isNullOrEmpty()
    val needsResponse =
      packet.getDirection() == Packet.Direction.SERVER &&
        packet.getSummarizedResponseColumn().isNullOrEmpty()
    return needsRequest || needsResponse
  }

  /**
   * 永続要約が空の既存行（summarized_request 導入前のDBなど）向けに、BLOBから要約を再計算して DBへ書き戻す。次回以降のメタデータ読みでも
   * Request/Response 列が埋まる。
   */
  private fun backfillPersistedSummariesIfNeeded(packet: Packet) {
    if (!needsPersistedSummaryBackfill(packet)) {
      return
    }
    try {
      packet.refreshPersistedSummaries(packetSummarizer)
      packets.updatePersistedSummaries(
        packet.getId(),
        packet.getSummarizedRequestColumn(),
        packet.getSummarizedResponseColumn(),
        packet.getDisplayLength(),
        notify = false,
      )
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  fun resetCustomColoring() {
    colorManager.clear()
    table.repaint()
  }

  fun addCustomColoring(packetId: Int, color: Color) {
    colorManager.add(packetId, color)
    table.repaint()
  }

  fun removeCustomColoring(packetId: Int) {
    colorManager.clear(packetId)
    table.repaint()
  }

  fun addCustomColoringToCursorPos(color: Color) {
    addCustomColoring(selectedPacketId, color)
  }

  fun containsColor(): Boolean = colorManager.contains(selectedPacketId)

  val color: Color
    get() = colorManager.getColor(selectedPacketId)

  fun getSelectedIndex(): Int = table.selectedRow

  fun addMenu(menuItem: JMenuItem) {
    menu.add(menuItem)
  }

  fun removeMenu(menuItem: JMenuItem) {
    menu.remove(menuItem)
  }

  fun getResponsePacketIdForRequest(requestPacketId: Int): Int =
    pairingService.getResponsePacketIdForRequest(requestPacketId)

  fun isSelectedRowMerged(): Boolean = pairingService.isMergedRow(selectedPacketId)

  private fun createFilterPanel(): JComponent {
    guiFilter =
      HintTextField(i18nString("filter string... (ex: request == example.com && type == image)"))
    guiFilter.maximumSize = Dimension(Short.MAX_VALUE.toInt(), guiFilter.minimumSize.height)
    guiFilter.addKeyListener(
      object : KeyAdapter() {
        override fun keyPressed(event: KeyEvent) {
          try {
            if (event.keyCode == KeyEvent.VK_ENTER) {
              filter()
            }
          } catch (_: Exception) {
            // Nothing to do
          }
        }
      }
    )
    guiFilter.addFocusListener(
      object : FocusAdapter() {
        override fun focusLost(event: java.awt.event.FocusEvent) {
          filter()
        }
      }
    )

    val buttonWidth = 35
    val filterConfigAdd = JButton(ImageIcon(javaClass.getResource("/gui/plus.png")))
    configureFilterButton(filterConfigAdd, buttonWidth)
    filterConfigAdd.addActionListener {
      try {
        val dialog = GUIFilterConfigAddDialog(owner, guiFilter.text)
        dialog.showDialog()
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }

    val filterDropDown = JToggleButton(ImageIcon(javaClass.getResource("/gui/arrow.png")))
    configureFilterButton(filterDropDown, buttonWidth)
    filterDropDown.addMouseListener(
      object : MouseAdapter() {
        var dialog: GUIFilterDropDownList? = null

        override fun mouseReleased(event: MouseEvent) {
          try {
            val currentDialog = dialog
            if (currentDialog != null) {
              currentDialog.dispose()
              dialog = null
              filterDropDown.isSelected = false
              return
            }
            val x = guiFilter.locationOnScreen.x
            val y = guiFilter.locationOnScreen.y + guiFilter.height
            val width = guiFilter.width
            dialog =
              GUIFilterDropDownList(owner, width) { selectedFilter ->
                try {
                  guiFilter.text = selectedFilter.getFilter()
                  filterDropDown.isSelected = false
                  filter()
                  dialog?.dispose()
                  dialog = null
                } catch (exception: Exception) {
                  errWithStackTrace(exception)
                }
              }
            dialog!!.setBounds(x, y, width, 0)
            val height = dialog!!.showDialog()
            dialog!!.setBounds(x, y, width, height)
            filterDropDown.isSelected = true
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    )

    val filterConfig = JButton(ImageIcon(javaClass.getResource("/gui/config.png")))
    configureFilterButton(filterConfig, buttonWidth)
    filterConfig.addActionListener {
      try {
        GUIFilterConfigDialog(owner).showDialog()
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }

    val filterPanel = JPanel()
    filterPanel.layout = BoxLayout(filterPanel, BoxLayout.X_AXIS)
    filterPanel.add(guiFilter)
    filterPanel.add(filterDropDown)
    filterPanel.add(filterConfigAdd)
    filterPanel.add(filterConfig)
    return filterPanel
  }

  private fun configureFilterButton(button: AbstractButton, buttonWidth: Int) {
    val size = Dimension(buttonWidth, guiFilter.maximumSize.height)
    button.preferredSize = size
    button.maximumSize = size
    button.minimumSize = size
    button.background = button.background
  }

  private fun addKeyboardNavigation(
    send: JMenuItem,
    sendToResender: JMenuItem,
    copy: JMenuItem,
    copyAll: JMenuItem,
  ) {
    table.addKeyListener(
      object : KeyAdapter() {
        override fun keyPressed(event: KeyEvent) {
          try {
            val maskKey = Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx
            when (event.keyCode) {
              KeyEvent.VK_J -> {
                var position = table.selectedRow + 1
                position = if (position >= table.rowCount) table.rowCount - 1 else position
                table.changeSelection(position, 0, false, false)
              }
              KeyEvent.VK_K -> {
                var position = table.selectedRow - 1
                position = if (position < 0) 0 else position
                table.changeSelection(position, 0, false, false)
              }
              KeyEvent.VK_Y -> {
                if (event.modifiersEx and maskKey == maskKey) {
                  copy.doClick()
                  return
                }
              }
              KeyEvent.VK_S -> {
                if (event.modifiersEx and maskKey == maskKey) {
                  send.doClick()
                }
              }
              KeyEvent.VK_R -> {
                if (event.modifiersEx and maskKey == maskKey) {
                  sendToResender.doClick()
                }
              }
              KeyEvent.VK_M -> {
                if (event.modifiersEx and maskKey == maskKey) {
                  copyAll.doClick()
                }
              }
            }
            preferredPosition = selectedPacketId
          } catch (_: Exception) {
            // Nothing to do
          }
        }
      }
    )
  }

  private fun addTableMouseListeners() {
    table.addMouseListener(
      object : MouseAdapter() {
        override fun mouseReleased(event: MouseEvent) {
          if (Utils.isWindows() && event.isPopupTrigger) {
            menu.show(event.component, event.x, event.y)
          }
          autoScroll.doDisable()
        }

        override fun mousePressed(event: MouseEvent) {
          try {
            if (event.isPopupTrigger) {
              menu.show(event.component, event.x, event.y)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    )
  }

  private fun addTableResizeListener() {
    table.addComponentListener(
      object : ComponentAdapter() {
        override fun componentResized(event: ComponentEvent) {
          try {
            if (!autoScroll.isEnabled()) {
              return
            }
            table.scrollRectToVisible(table.getCellRect(table.rowCount - 1, 0, true))
            table.changeSelection(table.rowCount - 1, 0, false, false)
            val packetId = selectedPacketId
            historyUpdateService.submit {
              var packet = requireNotNull(packets.query(packetId))
              var retryCount = 10
              while (packet.getDecodedData().isEmpty()) {
                if (retryCount-- <= 0) {
                  break
                }
                Thread.sleep(100)
                packet = requireNotNull(packets.query(packetId))
              }
              SwingUtilities.invokeLater {
                try {
                  resolveAndShowPacket(packet, false)
                } catch (exception: Exception) {
                  errWithStackTrace(exception)
                }
              }
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    )
  }

  private fun saveHistoryWithAlertDialog() {
    if (dialogOnce) {
      return
    }
    dialogOnce = true
    JOptionPane.showMessageDialog(
      owner,
      i18nString("Database size is approaching the limit (2GB). Please save History."),
      i18nString("Warning"),
      JOptionPane.WARNING_MESSAGE,
    )
    val fileChooser = WriteFileChooserWrapper(owner, "sqlite3")
    fileChooser.addFileChooserListener(
      object : WriteFileChooserWrapper.FileChooserListener {
        override fun onApproved(file: File, extension: String) {
          try {
            main.modelServices.database.Save(file.absolutePath)
            JOptionPane.showMessageDialog(null, i18nString("Data saved successfully"))
            updateRequest(true)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
            JOptionPane.showMessageDialog(null, i18nString("Data can't be saved with error"))
          }
          dialogOnce = false
        }

        override fun onCanceled() {}

        override fun onError() {
          JOptionPane.showMessageDialog(null, i18nString("Data can't be saved with error"))
        }
      }
    )
    fileChooser.showSaveDialog()
  }

  private fun handlePacketsPropertyChange(event: PropertyChangeEvent) {
    when (val value = event.newValue) {
      is Int -> scheduleIntegerPacketUpdate(value)
      else ->
        SwingUtilities.invokeLater {
          try {
            when (value) {
              is Boolean -> handleBooleanPacketValue(value)
              DatabaseMessage.RECONNECT -> updateAllAsync()
              else -> updateRequest(true)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
    }
  }

  // 大量のInt値(packet id)通知が短時間に届いても、EDT上のinvokeLaterを1回にまとめてから
  // まとめて処理することで、EDTタスクの積み増しによるコマ落ちを防ぐ。
  private fun scheduleIntegerPacketUpdate(value: Int) {
    packetNotificationCoalescer.offer(value)
    if (!intPacketUpdateScheduled.compareAndSet(false, true)) {
      return
    }
    SwingUtilities.invokeLater { drainPendingIntegerPacketUpdates() }
  }

  private fun drainPendingIntegerPacketUpdates() {
    intPacketUpdateScheduled.set(false)
    val values = packetNotificationCoalescer.drain()
    historyUpdateService.submit {
      try {
        // create を update より先に処理し、CLIENT 行登録後に SERVER をマージできるようにする
        val (createNotifications, updateIds) =
          PacketHistoryNotificationCoalescer.partitionCreatesBeforeUpdates(values)
        val createdPackets = ArrayList<Packet>(createNotifications.size)
        for (value in createNotifications) {
          val packet = packets.queryByIdMetadata(-value) ?: continue
          createdPackets.add(packet)
        }
        SwingUtilities.invokeLater {
          try {
            for (packet in createdPackets) {
              handleLoadedCreatedPacket(packet)
            }
            for (id in updateIds) {
              updateRequestOne(id)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }
  }

  private fun handleBooleanPacketValue(value: Boolean) {
    if (value) {
      saveHistoryWithAlertDialog()
    }
  }

  private fun handleIntegerPacketValue(value: Int) {
    if (value >= 0) {
      updateRequestOne(value)
      return
    }
    val packet = requireNotNull(packets.queryByIdMetadata(-value))
    handleLoadedCreatedPacket(packet)
  }

  private fun handleLoadedCreatedPacket(packet: Packet) {
    val packetId = packet.getId()
    val groupId = packet.getGroup()
    val isResponse = packet.getDirection() == Packet.Direction.SERVER
    val packetCount = countAndTrackPacket(packet)
    if (shouldUnmergeExisting(packetCount, groupId)) {
      unmergeExistingPairing(groupId)
    }
    if (shouldMergeResponse(groupId, isResponse)) {
      mergeResponseIntoRequestRow(packet, groupId, packetId, true)
    } else {
      addNewRowWithGroupTracking(packet, packetId, isResponse, groupId)
    }
  }

  private fun countAndTrackPacket(packet: Packet): Int {
    val groupId = packet.getGroup()
    if (groupId == 0L) {
      return 0
    }
    val packetCount = pairingService.incrementGroupPacketCount(groupId)
    if (packet.getDirection() == Packet.Direction.CLIENT) {
      pairingService.incrementGroupClientPacketCount(groupId)
    }
    return packetCount
  }

  private fun shouldMergeResponse(groupId: Long, isResponse: Boolean): Boolean =
    isResponse &&
      groupId != 0L &&
      pairingService.containsGroup(groupId) &&
      !pairingService.hasResponse(groupId) &&
      pairingService.isGroupMergeable(groupId)

  private fun shouldUnmergeExisting(packetCount: Int, groupId: Long): Boolean =
    packetCount == 3 && pairingService.containsGroup(groupId) && pairingService.hasResponse(groupId)

  private fun getDisplayData(packet: Packet): ByteArray =
    if (packet.getDecodedData().isNotEmpty()) packet.getDecodedData() else packet.getModifiedData()

  private fun resolveContentType(requestPacket: Packet, responsePacket: Packet): String? {
    var contentType = requestPacket.getContentType()
    if (contentType == null || contentType.isEmpty()) {
      contentType = responsePacket.getContentType()
    }
    return contentType
  }

  private fun mergeResponseIntoRequestRow(
    responsePacket: Packet,
    groupId: Long,
    responsePacketId: Int,
    refreshSelection: Boolean,
  ) {
    val rowIndex = pairingService.getRowForGroup(groupId) ?: return
    val requestPacketId = tableModel.getValueAt(rowIndex, COL_ID) as Int
    tableModel.setValueAt(
      responsePacket.getSummarizedResponse(packetSummarizer),
      rowIndex,
      COL_SERVER_RESPONSE,
    )
    val currentLength = tableModel.getValueAt(rowIndex, COL_LENGTH) as Int
    tableModel.setValueAt(currentLength + displayLengthOf(responsePacket), rowIndex, COL_LENGTH)
    val existingContentType = tableModel.getValueAt(rowIndex, COL_CONTENT_TYPE) as? String
    val contentType =
      if (existingContentType.isNullOrEmpty()) responsePacket.getContentType()
      else existingContentType
    tableModel.setValueAt(contentType, rowIndex, COL_CONTENT_TYPE)
    val currentModified = tableModel.getValueAt(rowIndex, COL_MODIFIED) as Boolean
    tableModel.setValueAt(currentModified || responsePacket.getModified(), rowIndex, COL_MODIFIED)
    pairingService.markGroupHasResponse(groupId)
    pairingService.registerPairing(responsePacketId, requestPacketId)
    idRow[responsePacketId] = rowIndex
    if (refreshSelection && requestPacketId == selectedPacketId) {
      historyUpdateService.submit {
        val requestPacket = packets.query(requestPacketId) ?: return@submit
        SwingUtilities.invokeLater {
          try {
            resolveAndShowPacket(requestPacket, true)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    }
  }

  private fun mergeResponseMappingOnly(responsePacketId: Int, groupId: Long) {
    val rowIndex = pairingService.getRowForGroup(groupId) ?: return
    val requestPacketId = tableModel.getValueAt(rowIndex, COL_ID) as Int
    pairingService.markGroupHasResponse(groupId)
    pairingService.registerPairing(responsePacketId, requestPacketId)
    idRow[responsePacketId] = rowIndex
  }

  private fun addNewRowWithGroupTracking(
    packet: Packet,
    packetId: Int,
    isResponse: Boolean,
    groupId: Long,
  ) {
    tableModel.addRow(makeRowDataFromPacket(packet))
    val rowIndex = tableModel.rowCount - 1
    idRow[packetId] = rowIndex
    if (!isResponse && groupId != 0L) {
      pairingService.registerGroupRow(groupId, rowIndex)
    }
  }

  private fun addNewAsyncPlaceholderRowWithGroupTracking(
    packetId: Int,
    isResponse: Boolean,
    groupId: Long,
  ) {
    tableModel.addRow(
      arrayOf(
        packetId,
        "Loading...",
        "Loading...",
        0,
        "Loading...",
        "",
        "Loading...",
        "",
        "00:00:00 1900/01/01 Z",
        false,
        false,
        "",
        "",
        "",
        -1L,
      )
    )
    val rowIndex = tableModel.rowCount - 1
    idRow[packetId] = rowIndex
    if (!isResponse && groupId != 0L) {
      pairingService.registerGroupRow(groupId, rowIndex)
    }
  }

  private fun trackRequestGroupIfNeeded(packetId: Int, groupId: Long) {
    if (groupId == 0L) {
      return
    }
    val rowIndex = idRow[packetId] ?: return
    pairingService.ensureGroupTracked(groupId, rowIndex)
  }

  private fun resolveAndShowPacket(packet: Packet, forceRefresh: Boolean) {
    val responsePacketId = pairingService.getResponsePacketIdForRequest(packet.getId())
    if (responsePacketId != -1) {
      guiPacket.setPackets(packet, packets.query(responsePacketId), forceRefresh)
      return
    }
    if (pairingService.containsResponsePairing(packet.getId())) {
      val requestPacketId = pairingService.getRequestIdForResponse(packet.getId())
      guiPacket.setPackets(packets.query(requestPacketId), packet, forceRefresh)
      return
    }
    val groupId = packet.getGroup()
    if (
      (groupId != 0L && pairingService.isGroupStreaming(groupId)) ||
        packet.getDirection() == Packet.Direction.SERVER
    ) {
      guiPacket.setSinglePacket(packet, forceRefresh)
      return
    }
    guiPacket.setPackets(packet, null, forceRefresh)
  }

  private fun unmergeExistingPairing(groupId: Long) {
    val rowIndex = pairingService.getRowForGroup(groupId) ?: return
    val requestPacketId = tableModel.getValueAt(rowIndex, COL_ID) as Int
    val responsePacketId = pairingService.unregisterPairingByRequestId(requestPacketId)
    pairingService.unmergeGroup(groupId)
    if (responsePacketId == -1) {
      return
    }
    val requestMeta = packets.queryByIdMetadata(requestPacketId)
    tableModel.setValueAt("", rowIndex, COL_SERVER_RESPONSE)
    if (requestMeta != null) {
      tableModel.setValueAt(displayLengthOf(requestMeta), rowIndex, COL_LENGTH)
    }
    val responsePacket = packets.queryByIdMetadata(responsePacketId)
    if (responsePacket != null) {
      tableModel.addRow(makeRowDataFromPacket(responsePacket))
      idRow[responsePacketId] = tableModel.rowCount - 1
    }
    if (requestPacketId == selectedPacketId) {
      historyUpdateService.submit {
        val requestPacket = packets.query(requestPacketId) ?: return@submit
        SwingUtilities.invokeLater {
          try {
            resolveAndShowPacket(requestPacket, true)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    }
  }

  private fun handleFiltersPropertyChange(event: PropertyChangeEvent) {
    SwingUtilities.invokeLater {
      try {
        if (event.newValue == DatabaseMessage.RECONNECT) {
          updateAllAsync()
        } else {
          filter()
        }
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }
  }

  private fun handleDatabaseMessagePropertyChange(event: PropertyChangeEvent) {
    SwingUtilities.invokeLater {
      try {
        if (event.newValue == DatabaseMessage.RECONNECT) {
          updateAllAsync()
        }
      } catch (exception: Exception) {
        errWithStackTrace(exception)
      }
    }
  }

  private fun updateRequest(cursorUpdate: Boolean) {
    val selectedId = selectedPacketId
    val worker =
      object : SwingWorker<Packet?, Packet>() {
        override fun doInBackground(): Packet? {
          val updateTargets: HashSet<Int>
          synchronized(updatePacketIds) {
            updateTargets = HashSet(updatePacketIds)
            updatePacketIds.clear()
          }
          for (id in updateTargets) {
            packets.queryByIdMetadata(id)?.let { publish(it) }
          }
          return if (cursorUpdate) packets.query(selectedId) else null
        }

        override fun process(packets: List<Packet>) {
          try {
            for (packet in packets) {
              updateOne(packet)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }

        override fun done() {
          try {
            get()?.let { resolveAndShowPacket(it, false) }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    historyUpdateService.submit(worker)
  }

  private fun unmergeExistingPairingInAsyncModel(groupId: Long) {
    val rowIndex = pairingService.getRowForGroup(groupId) ?: return
    val requestPacketId = tableModel.getValueAt(rowIndex, COL_ID) as Int
    val responsePacketId = pairingService.unregisterPairingByRequestId(requestPacketId)
    pairingService.unmergeGroup(groupId)
    if (responsePacketId == -1) {
      return
    }
    tableModel.addRow(
      arrayOf(
        responsePacketId,
        "Loading...",
        "Loading...",
        0,
        "Loading...",
        "",
        "Loading...",
        "",
        "00:00:00 1900/01/01 Z",
        false,
        false,
        "",
        "",
        "",
        -1L,
      )
    )
    idRow[responsePacketId] = tableModel.rowCount - 1
  }

  private fun updateOne(packet: Packet?) {
    if (packet == null) {
      return
    }
    val packetId = packet.getId()
    val isResponse = packet.getDirection() == Packet.Direction.SERVER
    val groupId = packet.getGroup()
    if (!isResponse && groupId != 0L) {
      trackRequestGroupIfNeeded(packetId, groupId)
    }
    if (isResponse && pairingService.containsResponsePairing(packetId)) {
      val rowIndex = idRow[packetId]
      if (rowIndex != null) {
        tableModel.setValueAt(
          packet.getSummarizedResponse(packetSummarizer),
          rowIndex,
          COL_SERVER_RESPONSE,
        )
        val requestPacketId = pairingService.getRequestIdForResponse(packetId)
        val requestPacket = packets.queryByIdMetadata(requestPacketId)
        val requestLength =
          if (requestPacket != null) displayLengthOf(requestPacket)
          else (tableModel.getValueAt(rowIndex, COL_LENGTH) as? Int ?: 0)
        tableModel.setValueAt(requestLength + displayLengthOf(packet), rowIndex, COL_LENGTH)
        val contentType =
          if (requestPacket != null) resolveContentType(requestPacket, packet)
          else packet.getContentType()
        tableModel.setValueAt(contentType, rowIndex, COL_CONTENT_TYPE)
        val currentModified = tableModel.getValueAt(rowIndex, COL_MODIFIED) as Boolean
        tableModel.setValueAt(currentModified || packet.getModified(), rowIndex, COL_MODIFIED)
      }
      return
    }
    val rowIndex = idRow[packetId]
    if (rowIndex == null || rowIndex < 0 || rowIndex >= tableModel.rowCount) {
      return
    }
    val rowData = makeRowDataFromPacket(packet)
    val isMergedRequestRow = pairingService.isMergedRow(packetId)
    for (i in columnNames.indices) {
      if (isMergedRequestRow && (i == COL_SERVER_RESPONSE || i == COL_LENGTH)) {
        continue
      }
      if (rowData[i] === tableModel.getValueAt(rowIndex, i)) {
        continue
      }
      tableModel.setValueAt(rowData[i], rowIndex, i)
    }
  }

  private fun displayLengthOf(packet: Packet): Int {
    val persisted = packet.getDisplayLength()
    if (persisted > 0) {
      return persisted
    }
    return getDisplayData(packet).size
  }

  private fun makeRowDataFromPacket(packet: Packet): Array<Any?> {
    val clientIp = packet.getClientIP() ?: ""
    val clientPort = if (packet.getClientPort() == 0) "" else packet.getClientPort().toString()
    val serverIp = packet.getServerIP() ?: ""
    val serverPort = if (packet.getServerPort() == 0) "" else packet.getServerPort().toString()
    val dateFormat = SimpleDateFormat("MM/dd HH:mm:ss")
    return arrayOf(
      packet.getId(),
      packet.getSummarizedRequest(packetSummarizer),
      packet.getSummarizedResponse(packetSummarizer),
      displayLengthOf(packet),
      clientIp,
      clientPort,
      serverIp,
      serverPort,
      dateFormat.format(packet.getDate()),
      packet.getResend(),
      packet.getModified(),
      packet.getContentType(),
      packet.getEncoder(),
      packet.getAlpn(),
      packet.getGroup(),
    )
  }

  private fun applyNumericColumnAlignment() {
    val rightAligned = DefaultTableCellRenderer()
    rightAligned.horizontalAlignment = SwingConstants.RIGHT
    for (columnIndex in NUMERIC_RIGHT_ALIGNED_COLUMNS) {
      table.getColumn(columnNames[columnIndex]).cellRenderer = rightAligned
    }
  }

  private fun sortByText(text: String): Boolean {
    if (text.isEmpty()) {
      sorter.rowFilter = null
      return true
    }
    try {
      sorter.rowFilter = FilterTextParser.parse(text, tableModel, packets)
      return true
    } catch (_: ParseException) {
      // Nothing to do
    } catch (_: NumberFormatException) {
      // Nothing to do
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
    return false
  }

  companion object {
    private val COL_ID = 0
    private val COL_SERVER_RESPONSE = 2
    private val COL_LENGTH = 3
    private val COL_CLIENT_PORT = 5
    private val COL_SERVER_PORT = 7
    private val COL_RESEND = 9
    private val COL_MODIFIED = 10
    private val COL_CONTENT_TYPE = 11
    private val NUMERIC_RIGHT_ALIGNED_COLUMNS =
      intArrayOf(COL_ID, COL_SERVER_RESPONSE, COL_LENGTH, COL_CLIENT_PORT, COL_SERVER_PORT)
    private const val SKELETON_PAGE_SIZE = 500L
    private const val FILL_PAGE_SIZE = 100L
  }
}
