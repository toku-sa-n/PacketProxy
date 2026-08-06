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
package packetproxy.model

import com.google.common.primitives.Bytes
import difflib.Chunk
import difflib.Delta
import difflib.DiffUtils
import packetproxy.util.errWithStackTrace

class DiffBinary() : DiffBase() {
  // static public void main(String[] args) {
  // try {
  // diff.markAsOriginal("hello\nw orld\naaaa\nhoge".getBytes());
  // diff.markAsTarget("hello\nworld\nhoge".getBytes());
  // diff.diff(new DiffEventAdapter() {
  // @Override public void foundDelDelta(int pos, int length) throws Exception {
  // Logging.log(String.format("Orig DEL: %d %d", pos, length)); }
  // @Override public void foundInsDelta(int pos, int length) throws Exception {
  // Logging.log(String.format("Orig INS: %d %d", pos, length)); }
  // @Override public void foundChgDelta(int pos, int length) throws Exception {
  // Logging.log(String.format("Orig CHG: %d %d", pos, length)); }
  // }, new DiffEventAdapter() {
  // @Override public void foundDelDelta(int pos, int length) throws Exception {
  // Logging.log(String.format("Targ DEL: %d %d", pos, length)); }
  // @Override public void foundInsDelta(int pos, int length) throws Exception {
  // Logging.log(String.format("Targ INS: %d %d", pos, length)); }
  // @Override public void foundChgDelta(int pos, int length) throws Exception {
  // Logging.log(String.format("Targ CHG: %d %d", pos, length)); }
  // });
  // } catch (Exception e) {
  // errWithStackTrace(e);
  // }
  // }

  companion object {

    @JvmStatic
    @Throws(Exception::class)
    fun diffPerCharacter(
      set: DiffSet,
      original_event: DiffEventListener,
      target_event: DiffEventListener,
    ) {
      try {
        val listOrig = Bytes.asList(*set.getOriginal()!!)
        val listTarg = Bytes.asList(*set.getTarget()!!)

        val diff = DiffUtils.diff(listOrig, listTarg)

        val deltas = diff.deltas
        for (delta in deltas) {
          val chunkOrig = delta.original
          val chunkTarg = delta.revised
          if (delta.getType() == Delta.TYPE.CHANGE) {
            original_event.foundChgDelta(
              chunkPositionPerByte(listOrig, chunkOrig),
              chunkLengthPerByte(chunkOrig),
            )
            target_event.foundChgDelta(
              chunkPositionPerByte(listTarg, chunkTarg),
              chunkLengthPerByte(chunkTarg),
            )
          } else if (delta.getType() == Delta.TYPE.INSERT) {
            target_event.foundInsDelta(
              chunkPositionPerByte(listTarg, chunkTarg),
              chunkLengthPerByte(chunkTarg),
            )
          } else if (delta.getType() == Delta.TYPE.DELETE) {
            original_event.foundDelDelta(
              chunkPositionPerByte(listOrig, chunkOrig),
              chunkLengthPerByte(chunkOrig),
            )
          }
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    @JvmStatic
    @Throws(Exception::class)
    fun diffPerLine(
      set: DiffSet,
      original_event: DiffEventListener,
      target_event: DiffEventListener,
    ) {}

    @JvmStatic
    protected fun sumOfBytesPerByte(list: List<Byte>): Int {
      val i = list.size
      if (i == 0) {
        return 0
      }
      return 2 * i + (i - 1)
    }

    private fun chunkPositionPerByte(lines: List<Byte>, a: Chunk): Int {
      val index = a.getPosition()
      val sublines = lines.subList(0, index)
      return sumOfBytesPerByte(sublines) + 1
    }

    private fun chunkLengthPerByte(a: Chunk): Int {
      val lines = a.getLines()
      val byteLines = ArrayList<Byte>()
      for (line in lines) {
        byteLines.add(line as Byte)
      }
      return sumOfBytesPerByte(byteLines)
    }
  }
}
