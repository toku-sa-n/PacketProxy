package packetproxy.gui

import java.awt.Frame
import java.awt.GraphicsEnvironment
import java.awt.Rectangle
import java.awt.event.ComponentAdapter
import java.awt.event.ComponentEvent
import java.util.prefs.Preferences
import javax.swing.JFrame
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.event.ChangeEvent
import javax.swing.event.ListSelectionEvent
import javax.swing.event.TableColumnModelEvent
import javax.swing.event.TableColumnModelListener

/**
 * ウィンドウサイズ・分割位置・テーブル列幅などの画面レイアウトを、プロジェクトDBではなくユーザ設定領域 (java.util.prefs)
 * に永続化する。プロジェクトを切り替えても同じレイアウトで作業を続けられるようにするため。
 */
internal object WindowLayoutStore {
  const val MAIN_WINDOW = "mainWindow"
  const val HISTORY_SPLIT = "history.split"
  const val HISTORY_TABLE = "history.table"

  private val preferences: Preferences = Preferences.userRoot().node("packetproxy").node("layout")

  /** 保存済みのウィンドウ位置・サイズを復元する。保存値がない場合は defaultBounds を使う。 */
  fun restoreFrameBounds(key: String, frame: JFrame, defaultBounds: Rectangle) {
    val width = preferences.getInt("$key.width", -1)
    val height = preferences.getInt("$key.height", -1)
    if (width <= 0 || height <= 0) {
      frame.bounds = defaultBounds
      return
    }
    val x = preferences.getInt("$key.x", defaultBounds.x)
    val y = preferences.getInt("$key.y", defaultBounds.y)
    val bounds = Rectangle(x, y, width, height)
    frame.bounds =
      if (isVisibleOnAnyScreen(bounds)) bounds
      else Rectangle(defaultBounds.x, defaultBounds.y, width, height)
    if (preferences.getBoolean("$key.maximized", false)) {
      frame.extendedState = frame.extendedState or Frame.MAXIMIZED_BOTH
    }
  }

  /** ウィンドウのリサイズ・移動・最大化のたびにレイアウトを保存する。 */
  fun trackFrameBounds(key: String, frame: JFrame) {
    frame.addComponentListener(
      object : ComponentAdapter() {
        override fun componentResized(event: ComponentEvent) = saveFrameBounds(key, frame)

        override fun componentMoved(event: ComponentEvent) = saveFrameBounds(key, frame)
      }
    )
    frame.addWindowStateListener { saveFrameBounds(key, frame) }
  }

  fun saveFrameBounds(key: String, frame: JFrame) {
    val maximized = frame.extendedState and Frame.MAXIMIZED_BOTH == Frame.MAXIMIZED_BOTH
    preferences.putBoolean("$key.maximized", maximized)
    // 最大化中のサイズを保存すると解除時に戻すサイズを失うため、通常状態のサイズだけを保存する
    if (maximized) {
      return
    }
    val bounds = frame.bounds
    if (bounds.width <= 0 || bounds.height <= 0) {
      return
    }
    preferences.putInt("$key.x", bounds.x)
    preferences.putInt("$key.y", bounds.y)
    preferences.putInt("$key.width", bounds.width)
    preferences.putInt("$key.height", bounds.height)
  }

  fun restoreDividerLocation(key: String, splitPane: JSplitPane) {
    val location = preferences.getInt("$key.divider", -1)
    if (location <= 0) {
      return
    }
    splitPane.dividerLocation = location
  }

  fun saveDividerLocation(key: String, splitPane: JSplitPane) {
    val location = splitPane.dividerLocation
    if (location <= 0) {
      return
    }
    preferences.putInt("$key.divider", location)
  }

  fun trackDividerLocation(key: String, splitPane: JSplitPane) {
    splitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY) { event ->
      val location = event.newValue as? Int ?: return@addPropertyChangeListener
      if (location <= 0) {
        return@addPropertyChangeListener
      }
      preferences.putInt("$key.divider", location)
    }
  }

  /** 列数が保存時と一致する場合だけ列幅を復元する。列構成が変わった場合は既定値を使う。 */
  fun restoreColumnWidths(key: String, table: JTable) {
    val stored = preferences.get("$key.columnWidths", "")
    if (stored.isEmpty()) {
      return
    }
    val widths = stored.split(",").mapNotNull { it.trim().toIntOrNull() }
    if (widths.size != table.columnModel.columnCount) {
      return
    }
    widths.forEachIndexed { index, width ->
      if (width > 0) {
        table.columnModel.getColumn(index).preferredWidth = width
      }
    }
  }

  fun trackColumnWidths(key: String, table: JTable) {
    table.columnModel.addColumnModelListener(
      object : TableColumnModelListener {
        override fun columnMarginChanged(event: ChangeEvent) = saveColumnWidths(key, table)

        override fun columnAdded(event: TableColumnModelEvent) {}

        override fun columnRemoved(event: TableColumnModelEvent) {}

        override fun columnMoved(event: TableColumnModelEvent) {}

        override fun columnSelectionChanged(event: ListSelectionEvent) {}
      }
    )
  }

  fun saveColumnWidths(key: String, table: JTable) {
    val columnModel = table.columnModel
    if (columnModel.columnCount == 0) {
      return
    }
    val widths = (0 until columnModel.columnCount).map { columnModel.getColumn(it).preferredWidth }
    if (widths.any { it <= 0 }) {
      return
    }
    preferences.put("$key.columnWidths", widths.joinToString(","))
  }

  /** アプリ終了時などに、非同期フラッシュ待ちの設定値を確実に書き出す。 */
  fun flush() {
    preferences.flush()
  }

  private fun isVisibleOnAnyScreen(bounds: Rectangle): Boolean =
    GraphicsEnvironment.getLocalGraphicsEnvironment().screenDevices.any { device ->
      device.defaultConfiguration.bounds.intersects(bounds)
    }
}
