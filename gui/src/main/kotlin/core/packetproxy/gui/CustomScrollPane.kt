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
package packetproxy.gui

import java.awt.Component
import java.awt.event.MouseWheelEvent
import java.awt.event.MouseWheelListener
import javax.swing.JScrollBar
import javax.swing.JScrollPane

class CustomScrollPane : JScrollPane() {
  init {
    addMouseWheelListener(CustomMouseWheelListener())
  }

  inner class CustomMouseWheelListener : MouseWheelListener {
    private var bar: JScrollBar = this@CustomScrollPane.verticalScrollBar
    private var previousValue = 0
    private var parentScrollPane: JScrollPane? = null

    private fun getParentScrollPane(): JScrollPane? {
      if (parentScrollPane == null) {
        var parent: Component? = getParent()
        while (parent !is JScrollPane && parent != null) {
          parent = parent.parent
        }
        parentScrollPane = parent as JScrollPane?
      }
      return parentScrollPane
    }

    override fun mouseWheelMoved(e: MouseWheelEvent) {
      val parent = getParentScrollPane()
      if (parent != null) {
        if (e.wheelRotation < 0) {
          if (bar.value == 0 && previousValue == 0) {
            parent.dispatchEvent(cloneEvent(e))
          }
        } else {
          if (bar.value == getMax() && previousValue == getMax()) {
            parent.dispatchEvent(cloneEvent(e))
          }
        }
        previousValue = bar.value
      } else {
        this@CustomScrollPane.removeMouseWheelListener(this)
      }
    }

    private fun getMax(): Int = bar.maximum - bar.visibleAmount

    private fun cloneEvent(e: MouseWheelEvent): MouseWheelEvent =
      MouseWheelEvent(
        getParentScrollPane(),
        e.id,
        e.getWhen(),
        e.modifiersEx,
        1,
        1,
        e.clickCount,
        false,
        e.scrollType,
        e.scrollAmount,
        e.wheelRotation,
      )
  }
}
