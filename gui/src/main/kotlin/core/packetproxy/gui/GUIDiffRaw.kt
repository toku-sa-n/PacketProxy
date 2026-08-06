package packetproxy.gui

import java.awt.event.ActionListener
import javax.swing.JCheckBox
import javax.swing.JLabel
import packetproxy.common.i18nString
import packetproxy.model.Diff
import packetproxy.model.DiffEventAdapter
import packetproxy.model.DiffSet
import packetproxy.util.errWithStackTrace

class GUIDiffRaw(owner: GUIMain) : GUIDiffBase(owner) {
  private var jcCh = JCheckBox(i18nString("Character based (default: Line based)"))

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
      sortUniq(String(ds.getOriginal() ?: ByteArray(0))).toByteArray(),
      sortUniq(String(ds.getTarget() ?: ByteArray(0))).toByteArray(),
    )

  override fun update() {
    var current = owner.modelServices.diff.getSet() ?: return
    var ds = if (jc.isSelected) sortUniq(current) else current
    var originalData = ds.getOriginal() ?: return
    var targetData = ds.getTarget() ?: return
    textOrig.setData(originalData, false)
    textTarg.setData(targetData, false)
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
    if (jcCh.isSelected) Diff.diffPerCharacter(ds, original, target)
    else Diff.diffPerLine(ds, original, target)
  }
}
