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

import difflib.Chunk
import javax.swing.event.EventListenerList

abstract class DiffBase {
  // static public void main(String[] args) {
  // try {
  // Diff diff = Diff.getInstance();
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
  //
  constructor()

  protected var diffEventListenerList = EventListenerList()
  protected var orig: ByteArray? = null
  private var diffSet: DiffSet? = null

  fun isOriginalSet(): Boolean = if (this.orig != null) true else false

  @Throws(Exception::class)
  fun markAsOriginal(orig: ByteArray?) {
    if (orig != null && orig.size > 200 * 1024) {
      throw Exception("Text is Too Long!")
    }
    this.orig = orig
  }

  @Throws(Exception::class)
  fun clearAsOriginal() {
    this.orig = null
  }

  @Throws(Exception::class)
  fun markAsTarget(target: ByteArray?) {
    if (target != null && target.size > 200 * 1024) {
      throw Exception("Text is Too Long!")
    }
    this.diffSet = DiffSet(this.orig, target)
  }

  fun getSet(): DiffSet? = diffSet

  companion object {
    @JvmStatic
    protected fun sumOfCharactersPerLine(list: List<String>): Int =
      list.stream().mapToInt { s -> s.length + 1 }.sum()

    @JvmStatic
    protected fun sumOfCharactersPerCharacter(list: List<String>): Int =
      list.stream().mapToInt { s -> s.length }.sum()

    @JvmStatic
    protected fun chunkPositionPerLine(lines: List<String>, a: Chunk): Int {
      val index = a.getPosition()
      val sublines = lines.subList(0, index)
      return sumOfCharactersPerLine(sublines)
    }

    @JvmStatic
    protected fun chunkPositionPerCharacter(lines: List<String>, a: Chunk): Int {
      val index = a.getPosition()
      val sublines = lines.subList(0, index)
      return sumOfCharactersPerCharacter(sublines)
    }

    @JvmStatic
    protected fun chunkLengthPerLine(a: Chunk): Int =
      sumOfCharactersPerLine(a.getLines() as List<String>)

    @JvmStatic
    protected fun chunkLengthPerCharacter(a: Chunk): Int =
      sumOfCharactersPerCharacter(a.getLines() as List<String>)
  }
}
