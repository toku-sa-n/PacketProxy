package packetproxy.gui

import javax.swing.SwingUtilities

/** Swing部品の更新をEDT上で実行する。既にEDT上なら順序が入れ替わらないようその場で実行する。 */
internal fun onEDT(action: () -> Unit) {
  if (SwingUtilities.isEventDispatchThread()) {
    action()
    return
  }
  SwingUtilities.invokeLater(action)
}
