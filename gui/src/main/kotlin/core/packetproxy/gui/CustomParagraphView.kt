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

import javax.swing.text.Element
import javax.swing.text.FlowView
import javax.swing.text.ParagraphView
import javax.swing.text.View

class CustomParagraphView(element: Element) : ParagraphView(element) {
  init {
    strategy = CustomFlowStrategy()
  }

  private class CustomFlowStrategy : FlowView.FlowStrategy() {
    override fun createView(
      flowView: FlowView,
      startOffset: Int,
      spanLeft: Int,
      rowIndex: Int,
    ): View {
      var view = super.createView(flowView, startOffset, spanLeft, rowIndex)
      if (view.endOffset - view.startOffset > MAX_VIEW_SIZE) {
        view = view.createFragment(startOffset, startOffset + MAX_VIEW_SIZE)
      }
      return view
    }
  }

  companion object {
    private const val MAX_VIEW_SIZE = 100
  }
}
