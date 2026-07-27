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

import java.io.IOException
import java.io.Reader
import java.io.Writer
import javax.swing.text.AbstractDocument
import javax.swing.text.AttributeSet
import javax.swing.text.BadLocationException
import javax.swing.text.BoxView
import javax.swing.text.ComponentView
import javax.swing.text.Document
import javax.swing.text.Element
import javax.swing.text.IconView
import javax.swing.text.LabelView
import javax.swing.text.Segment
import javax.swing.text.StyleConstants
import javax.swing.text.StyledEditorKit
import javax.swing.text.View
import javax.swing.text.ViewFactory

class WrapEditorKit(private val savedData: ByteArray) : StyledEditorKit() {
  private var savedBuf = CharArray(0)
  private val defaultFactory: ViewFactory = WrapColumnFactory()

  fun getData(): ByteArray = savedData

  override fun getViewFactory(): ViewFactory = defaultFactory

  @Throws(IOException::class, BadLocationException::class)
  override fun read(input: Reader, document: Document, position: Int) {
    var buffer = CharArray(4096)
    var offset = position
    var attributes: AttributeSet = inputAttributes
    savedBuf = CharArray(0)
    var count = input.read(buffer, 0, buffer.size)
    while (count != -1) {
      document.insertString(offset, String(buffer, 0, count), attributes)
      savedBuf += buffer.copyOfRange(0, count)
      offset += count
      count = input.read(buffer, 0, buffer.size)
    }
  }

  @Throws(IOException::class, BadLocationException::class)
  override fun write(output: Writer, document: Document, position: Int, length: Int) {
    if (position < 0 || position + length > document.length) {
      throw BadLocationException("DefaultEditorKit.write", position)
    }
    var segment = Segment()
    var remaining = length
    var offset = position
    while (remaining > 0) {
      var count = minOf(remaining, 4096)
      document.getText(offset, count, segment)
      output.write(segment.array, segment.offset, segment.count)
      offset += count
      remaining -= count
    }
  }

  private class WrapColumnFactory : ViewFactory {
    override fun create(element: Element): View {
      return when (element.name) {
        AbstractDocument.ContentElementName -> WrapLabelView(element)
        AbstractDocument.ParagraphElementName -> CustomParagraphView(element)
        AbstractDocument.SectionElementName -> BoxView(element, View.Y_AXIS)
        StyleConstants.ComponentElementName -> ComponentView(element)
        StyleConstants.IconElementName -> IconView(element)
        else -> LabelView(element)
      }
    }
  }

  private class WrapLabelView(element: Element) : LabelView(element) {
    override fun getMinimumSpan(axis: Int): Float {
      return when (axis) {
        View.X_AXIS -> 0f
        View.Y_AXIS -> super.getMinimumSpan(axis)
        else -> throw IllegalArgumentException("Invalid axis: $axis")
      }
    }
  }
}
