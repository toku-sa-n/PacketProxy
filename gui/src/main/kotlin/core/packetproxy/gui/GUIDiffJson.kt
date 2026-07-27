package packetproxy.gui

import java.awt.event.ActionListener
import javax.swing.JCheckBox
import javax.swing.JLabel
import packetproxy.model.DiffEventAdapter
import packetproxy.model.DiffJson
import packetproxy.model.DiffSet
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.PacketProxyUtility

class GUIDiffJson : GUIDiffBase() {
  private var jcCh = JCheckBox("Character based (default: Line based)")

  init {
    jcCh.addActionListener(
      ActionListener {
        try {
          update()
        } catch (e: Exception) {
          errWithStackTrace(e)
        }
      }
    )
    jcPanel.add(JLabel("    "))
    jcPanel.add(jcCh)
  }

  override fun sortUniq(ds: DiffSet) =
    DiffSet(
      sortUniq(String(ds.getOriginal()!!)).toByteArray(),
      sortUniq(String(ds.getTarget()!!)).toByteArray(),
    )

  override fun update() {
    var ds =
      if (jc.isSelected) sortUniq(DiffJson.getInstance().getSet()!!)
      else DiffJson.getInstance().getSet()!!
    textOrig.setData(
      PacketProxyUtility.getInstance().prettyFormatJSONInRawData(ds.getOriginal()!!),
      false,
    )
    textTarg.setData(
      PacketProxyUtility.getInstance().prettyFormatJSONInRawData(ds.getTarget()!!),
      false,
    )
    docOrig = textOrig.getStyledDocument()
    docTarg = textTarg.getStyledDocument()
    docOrig.setCharacterAttributes(0, docOrig.length, defaultAttr, false)
    docTarg.setCharacterAttributes(0, docTarg.length, defaultAttr, false)
    var original =
      object : DiffEventAdapter() {
        override fun foundDelDelta(pos: Int, length: Int) {
          docOrig.setCharacterAttributes(pos, length, delAttr, false)
        }

        override fun foundChgDelta(pos: Int, length: Int) {
          docOrig.setCharacterAttributes(pos, length, chgAttr, false)
        }
      }
    var target =
      object : DiffEventAdapter() {
        override fun foundInsDelta(pos: Int, length: Int) {
          docTarg.setCharacterAttributes(pos, length, insAttr, false)
        }

        override fun foundChgDelta(pos: Int, length: Int) {
          docTarg.setCharacterAttributes(pos, length, chgAttr, false)
        }
      }
    if (jcCh.isSelected) DiffJson.diffPerCharacter(ds, original, target)
    else DiffJson.diffPerLine(ds, original, target)
  }
}
