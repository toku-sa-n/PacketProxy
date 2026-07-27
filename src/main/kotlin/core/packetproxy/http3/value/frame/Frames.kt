/*
 * Copyright 2023 DeNA Co., Ltd.
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
package packetproxy.http3.value.frame

import java.util.ArrayList
import java.util.function.Consumer
import java.util.function.Predicate

class Frames {
  private val frames = ArrayList<Frame>()

  private constructor()

  private constructor(frames: List<Frame>) {
    this.frames.addAll(frames)
  }

  fun clear() {
    frames.clear()
  }

  fun add(frame: Frame): Boolean = frames.add(frame)

  fun addAll(frames: Frames): Boolean = this.frames.addAll(frames.frames)

  operator fun get(index: Int): Frame = frames[index]

  fun size(): Int = frames.size

  fun isEmpty(): Boolean = frames.isEmpty()

  fun forEach(action: Consumer<Frame>) {
    frames.forEach(action)
  }

  fun anyMatch(pred: Predicate<Frame>): Boolean = frames.stream().anyMatch(pred)

  fun toList(): List<Frame> = frames.clone() as ArrayList<Frame>

  override fun toString(): String = "Frames(frames=$frames)"

  companion object {
    @JvmStatic fun emptyList(): Frames = Frames()

    @JvmStatic fun of(frame: Frame): Frames = Frames(listOf(frame))

    @JvmStatic fun of(frame1: Frame, frame2: Frame): Frames = Frames(listOf(frame1, frame2))

    @JvmStatic
    fun of(frame1: Frame, frame2: Frame, frame3: Frame): Frames =
      Frames(listOf(frame1, frame2, frame3))
  }
}
