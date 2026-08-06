package packetproxy.gui

import packetproxy.common.Binary
import packetproxy.model.DiffBinary
import packetproxy.model.DiffEventAdapter
import packetproxy.model.DiffSet
import packetproxy.util.errWithStackTrace

class GUIDiffBinary(owner: GUIMain) : GUIDiffBase(owner) {
  override fun sortUniq(ds: DiffSet): DiffSet {
    var original = ""
    var target = ""
    try {
      original = sortUniq(Binary(ds.getOriginal() ?: ByteArray(0)).toHexString().toString())
      target = sortUniq(Binary(ds.getTarget() ?: ByteArray(0)).toHexString().toString())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    return DiffSet(original.toByteArray(), target.toByteArray())
  }

  override fun update() {
    var current = owner.modelServices.diffBinary.getSet() ?: return
    var ds = if (jc.isSelected) sortUniq(current) else current
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
