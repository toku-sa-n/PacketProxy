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
package packetproxy.extensions.securityheaders

import java.awt.BorderLayout
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.net.URI
import javax.swing.JComponent
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.RowSorter.SortKey
import javax.swing.SwingUtilities
import javax.swing.table.DefaultTableModel
import javax.swing.table.TableRowSorter
import packetproxy.extensions.securityheaders.checks.*
import packetproxy.extensions.securityheaders.exclusion.ExclusionRule
import packetproxy.extensions.securityheaders.exclusion.ExclusionRuleManager
import packetproxy.extensions.securityheaders.exclusion.ExclusionRuleType
import packetproxy.extensions.securityheaders.ui.SecurityHeadersDetailPanel
import packetproxy.extensions.securityheaders.ui.SecurityHeadersTableRenderer
import packetproxy.extensions.securityheaders.ui.SecurityHeadersToolbar
import packetproxy.http.Http
import packetproxy.model.Extension
import packetproxy.model.Packet
import packetproxy.model.Packets

/**
 * Security Headers Extension for PacketProxy. Analyzes HTTP responses for security header
 * compliance.
 *
 * <p>
 * To add a new security check: 1. Create a new class implementing SecurityCheck interface 2. Add
 * the check to the SECURITY_CHECKS list in this class
 */
class SecurityHeadersExtension : Extension() {
  // ===== Registered Security Checks =====
  // Add new checks here to extend functionality
  companion object {
    private val SECURITY_CHECKS =
      listOf(
        CspCheck(),
        XssProtectionCheck(),
        HstsCheck(),
        ContentTypeCheck(),
        CacheControlCheck(),
        CookieCheck(),
        CorsCheck(),
      )
  }

  private var table: JTable? = null
  private var model: DefaultTableModel? = null
  private var sorter: TableRowSorter<DefaultTableModel>? = null
  private val endpointMap = mutableMapOf<String, Int>()
  private val packetMap = mutableMapOf<String, Packet>()
  private val resultsMap = mutableMapOf<String, Map<String, SecurityCheckResult>>()
  private var contextMenu: JPopupMenu? = null
  private val exclusionRuleManager = ExclusionRuleManager
  private var toolbar: SecurityHeadersToolbar? = null
  private var detailPanel: SecurityHeadersDetailPanel? = null

  init {
    setName("SecurityHeaders")
    exclusionRuleManager.addChangeListener { _ -> toolbar?.applyFilter() }
  }

  override fun createPanel(): JComponent {
    val panel = JPanel(BorderLayout())

    initializeTableModel()
    initializeTable()

    // Create toolbar with callbacks
    toolbar = SecurityHeadersToolbar(exclusionRuleManager, ::scanHistory, ::clearTable)
    toolbar?.setSorter(sorter!!)
    panel.add(toolbar!!.panel, BorderLayout.NORTH)

    // Create detail panel
    detailPanel = SecurityHeadersDetailPanel(SECURITY_CHECKS)

    val tableScrollPane = JScrollPane(table)
    val bottomSplit = detailPanel!!.createPanel()

    val mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, bottomSplit)
    mainSplit.dividerLocation = 300
    panel.add(mainSplit, BorderLayout.CENTER)

    setupSelectionListener()

    return panel
  }

  // ===== UI Component Creation =====

  private fun initializeTableModel() {
    // Build columns dynamically from registered checks
    val columns = mutableListOf<String>()
    columns.add("Method")
    columns.add("URL")
    columns.add("Server Response")
    for (check in SECURITY_CHECKS) {
      columns.add(check.getColumnName())
    }

    model =
      object : DefaultTableModel(columns.toTypedArray(), 0) {
        override fun isCellEditable(row: Int, column: Int): Boolean = false
      }
  }

  private fun initializeTable() {
    table = JTable(model)

    // Set up TableRowSorter for filtering
    sorter = TableRowSorter(model)
    table!!.rowSorter = sorter

    // Set custom header renderer (left-aligned text, sort icon on right)
    table!!.tableHeader.defaultRenderer = SecurityHeadersTableRenderer.HeaderRenderer(table!!)

    // Set custom cell renderer
    table!!.setDefaultRenderer(
      Any::class.java,
      SecurityHeadersTableRenderer.SecurityHeaderRenderer(
        table!!,
        model!!,
        SECURITY_CHECKS,
        resultsMap,
      ),
    )

    // Set column widths
    table!!.columnModel.getColumn(0).preferredWidth = 50 // Method
    table!!.columnModel.getColumn(1).preferredWidth = 300 // URL
    table!!.columnModel.getColumn(2).preferredWidth = 60 // HTTP Status Code
    // Security check columns
    for (i in SECURITY_CHECKS.indices) {
      table!!.columnModel.getColumn(SecurityHeadersTableRenderer.FIXED_COLUMNS + i).preferredWidth =
        80
    }

    // Default sort by URL ascending
    SwingUtilities.invokeLater {
      val sortKeys = mutableListOf<SortKey>()
      sortKeys.add(SortKey(1, javax.swing.SortOrder.ASCENDING)) // URL column
      sorter!!.sortKeys = sortKeys
    }

    // Setup context menu for right-click
    setupContextMenu()
  }

  private fun setupContextMenu() {
    contextMenu = JPopupMenu()

    val excludeHostItem = JMenuItem("Exclude this Host")
    excludeHostItem.addActionListener { excludeSelectedHost() }
    contextMenu!!.add(excludeHostItem)

    val excludePathItem = JMenuItem("Exclude this Path")
    excludePathItem.addActionListener { excludeSelectedPath() }
    contextMenu!!.add(excludePathItem)

    val excludeEndpointItem = JMenuItem("Exclude this Endpoint")
    excludeEndpointItem.addActionListener { excludeSelectedEndpoint() }
    contextMenu!!.add(excludeEndpointItem)

    table!!.addMouseListener(
      object : MouseAdapter() {
        override fun mousePressed(e: MouseEvent) {
          handleContextMenuTrigger(e)
        }

        override fun mouseReleased(e: MouseEvent) {
          handleContextMenuTrigger(e)
        }

        private fun handleContextMenuTrigger(e: MouseEvent) {
          if (e.isPopupTrigger) {
            val row = table!!.rowAtPoint(e.point)
            if (row >= 0 && row < table!!.rowCount) {
              table!!.setRowSelectionInterval(row, row)
            }
            contextMenu!!.show(e.component, e.x, e.y)
          }
        }
      }
    )
  }

  private fun excludeSelectedHost() {
    val viewRow = table!!.selectedRow
    if (viewRow == -1) return

    val modelRow = table!!.convertRowIndexToModel(viewRow)
    val url = model!!.getValueAt(modelRow, 1) as String
    val host = extractHostFromUrl(url)

    if (host != null) {
      exclusionRuleManager.addRule(ExclusionRule(ExclusionRuleType.HOST, host))
    }
  }

  private fun excludeSelectedPath() {
    val viewRow = table!!.selectedRow
    if (viewRow == -1) return

    val modelRow = table!!.convertRowIndexToModel(viewRow)
    val url = model!!.getValueAt(modelRow, 1) as String
    val path = extractPathFromUrl(url)

    if (path != null) {
      exclusionRuleManager.addRule(ExclusionRule(ExclusionRuleType.PATH, path))
    }
  }

  private fun excludeSelectedEndpoint() {
    val viewRow = table!!.selectedRow
    if (viewRow == -1) return

    val modelRow = table!!.convertRowIndexToModel(viewRow)
    val method = model!!.getValueAt(modelRow, 0) as String
    val url = model!!.getValueAt(modelRow, 1) as String

    val endpoint = "$method $url"
    exclusionRuleManager.addRule(ExclusionRule(ExclusionRuleType.ENDPOINT, endpoint))
  }

  private fun extractHostFromUrl(url: String): String? {
    return try {
      URI(url).host
    } catch (e: Exception) {
      null
    }
  }

  private fun extractPathFromUrl(url: String): String? {
    return try {
      val uri = URI(url)
      val path = uri.path
      if (path.isNullOrEmpty()) "/" else path
    } catch (e: Exception) {
      null
    }
  }

  // ===== Selection Listener =====

  private fun setupSelectionListener() {
    table!!.selectionModel.addListSelectionListener { event ->
      if (event.valueIsAdjusting) return@addListSelectionListener

      val viewRow = table!!.selectedRow
      if (viewRow == -1) return@addListSelectionListener

      val modelRow = table!!.convertRowIndexToModel(viewRow)
      val method = model!!.getValueAt(modelRow, 0) as String
      val url = model!!.getValueAt(modelRow, 1) as String
      val statusCode = model!!.getValueAt(modelRow, 2) as String
      val key = "$method $url $statusCode"

      val p = packetMap[key] ?: return@addListSelectionListener

      val results = resultsMap[key] ?: return@addListSelectionListener

      try {
        val http = Http.create(p.decodedData)
        val header = http.header

        detailPanel!!.populateHeaders(header, results)
        detailPanel!!.populateIssues(results)
      } catch (e: Exception) {
        e.printStackTrace()
      }
    }
  }

  // ===== Table Operations =====

  private fun clearTable() {
    SwingUtilities.invokeLater {
      model!!.rowCount = 0
      endpointMap.clear()
      packetMap.clear()
      resultsMap.clear()
      toolbar?.resetFilters()
    }
  }

  private fun scanHistory() {
    Thread {
        try {
          clearTable()
          val packets = Packets.getInstance().queryAll()
          val requestMap = mutableMapOf<Long, Packet>()

          for (p in packets) {
            if (p.direction == Packet.Direction.CLIENT) {
              requestMap[p.group] = p
            }
          }

          for (p in packets) {
            if (p.direction == Packet.Direction.SERVER) {
              val req = requestMap[p.group]
              if (req != null) {
                analyzePacket(p, req)
              }
            }
          }
        } catch (e: Exception) {
          e.printStackTrace()
        }
      }
      .start()
  }

  // ===== Packet Analysis =====

  private fun analyzePacket(resPacket: Packet, reqPacket: Packet) {
    try {
      val resHttp = Http.create(resPacket.decodedData)
      val reqHttp = Http.create(reqPacket.decodedData)

      val method = reqHttp.method
      val host = reqHttp.header.getValue("Host").orElse(reqPacket.serverName)
      val path = reqHttp.path
      val statusCode = resHttp.statusCode

      if (method == null || host == null || path == null || statusCode == null) {
        return
      }

      val url = (if (reqPacket.useSSL) "https://" else "http://") + host + path
      val endpointKey = "$method $url $statusCode"

      val header = resHttp.header

      // Run all security checks
      val context = mutableMapOf<String, Any>()
      // Pass request Origin header for CORS reflection detection
      val reqHeader = reqHttp.header
      reqHeader.getValue("Origin").ifPresent { origin -> context["requestOrigin"] = origin }

      val results = linkedMapOf<String, SecurityCheckResult>()

      for (check in SECURITY_CHECKS) {
        val result = check.check(header, context)
        results[check.getName()] = result
      }

      // Build row data
      val rowData = mutableListOf<Any>()
      rowData.add(method)
      rowData.add(url)
      rowData.add(statusCode)
      for (check in SECURITY_CHECKS) {
        val result = results[check.getName()]
        rowData.add(result?.getDisplayValue() ?: "")
      }

      val rowArray = rowData.toTypedArray()

      SwingUtilities.invokeLater {
        if (endpointMap.containsKey(endpointKey)) {
          val row = endpointMap[endpointKey]!!
          for (i in rowArray.indices) {
            model!!.setValueAt(rowArray[i], row, i)
          }
        } else {
          model!!.addRow(rowArray)
          endpointMap[endpointKey] = model!!.rowCount - 1
        }
        packetMap[endpointKey] = resPacket
        resultsMap[endpointKey] = results
      }
    } catch (e: Exception) {
      e.printStackTrace()
    }
  }
}
