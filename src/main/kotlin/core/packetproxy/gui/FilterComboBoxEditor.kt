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
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import javax.swing.ComboBoxEditor
import javax.swing.event.EventListenerList

class FilterComboBoxEditor : ComboBoxEditor {
  private val editor = HintTextField("フィルタ文字列　(ex: request == example.com && type == image)")
  private var caret = 0
  private val listenerList = EventListenerList()

  init {
    editor.addKeyListener(
      object : KeyAdapter() {
        override fun keyReleased(event: KeyEvent) {
          caret = editor.caretPosition
          fireActionEvent(editor.text)
        }
      }
    )
  }

  override fun addActionListener(listener: ActionListener) {
    listenerList.add(ActionListener::class.java, listener)
  }

  override fun getEditorComponent(): Component = editor

  override fun getItem(): Any = editor.text

  override fun removeActionListener(listener: ActionListener) {
    listenerList.remove(ActionListener::class.java, listener)
  }

  override fun selectAll() {}

  override fun setItem(newValue: Any?) {
    if (newValue !is String) {
      return
    }
    editor.text = newValue
    editor.caretPosition = caret
    fireActionEvent(newValue)
  }

  private fun fireActionEvent(value: String) {
    for (listener in listenerList.listenerList) {
      if (listener !is ActionListener) {
        continue
      }
      var event = ActionEvent(editor, ActionEvent.ACTION_PERFORMED, value)
      listener.actionPerformed(event)
    }
  }
}
