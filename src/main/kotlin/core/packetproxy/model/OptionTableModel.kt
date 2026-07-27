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

import javax.swing.table.DefaultTableModel
import org.apache.commons.lang3.ObjectUtils.Null

open class OptionTableModel(columnNames: Array<String>, rowNum: Int) :
  DefaultTableModel(columnNames, rowNum) {
  override fun getColumnClass(column: Int): Class<*> {
    if (rowCount == 0) {
      return Void::class.java
    }
    return getValueAt(0, column)?.javaClass ?: Null::class.java
  }
}
