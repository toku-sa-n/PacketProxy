package packetproxy.gui

import packetproxy.common.Binary
import packetproxy.model.DiffBinary
import packetproxy.model.DiffEventAdapter
import packetproxy.model.DiffSet
import packetproxy.util.Logging.errWithStackTrace

class GUIDiffBinary : GUIDiffBase() {
  override fun sortUniq(ds: DiffSet): DiffSet {
    var original = ""
    var target = ""
    try {
      original = sortUniq(Binary(ds.getOriginal()!!).toHexString().toString())
      target = sortUniq(Binary(ds.getTarget()!!).toHexString().toString())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    return DiffSet(original.toByteArray(), target.toByteArray())
  }

  override fun update() {
    var ds =
      if (jc.isSelected) sortUniq(DiffBinary.getInstance().getSet()!!)
      else DiffBinary.getInstance().getSet()!!
    var original = ds.getOriginal()
    var target = ds.getTarget()
    if (original != null)
      textOrig.setData(Binary(original).toHexString().toString().toByteArray(), false)
    if (target != null)
      textTarg.setData(Binary(target).toHexString().toString().toByteArray(), false)
    if (original == null || target == null) return
    docOrig = textOrig.getStyledDocument()
    docTarg = textTarg.getStyledDocument()
    docOrig.setCharacterAttributes(0, docOrig.length, defaultAttr, false)
    docTarg.setCharacterAttributes(0, docTarg.length, defaultAttr, false)
    var originalEvent =
      object : DiffEventAdapter() {
        override fun foundDelDelta(pos: Int, length: Int) {
          docOrig.setCharacterAttributes(pos, length, delAttr, false)
        }

        override fun foundChgDelta(pos: Int, length: Int) {
          docOrig.setCharacterAttributes(pos, length, chgAttr, false)
        }
      }
    var targetEvent =
      object : DiffEventAdapter() {
        override fun foundInsDelta(pos: Int, length: Int) {
          docTarg.setCharacterAttributes(pos, length, insAttr, false)
        }

        override fun foundChgDelta(pos: Int, length: Int) {
          docTarg.setCharacterAttributes(pos, length, chgAttr, false)
        }
      }
    DiffBinary.diffPerCharacter(ds, originalEvent, targetEvent)
  }
}
