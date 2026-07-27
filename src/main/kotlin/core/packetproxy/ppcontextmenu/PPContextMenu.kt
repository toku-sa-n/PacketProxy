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
package packetproxy.ppcontextmenu

import java.awt.event.ActionListener
import javax.swing.JMenuItem
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.Logging.log

abstract class PPContextMenu {
  @JvmField protected var menuItem: JMenuItem? = null
  @JvmField protected var dependentData: HashMap<String, Any>? = null

  abstract fun getLabelName(): String

  @Throws(Exception::class) abstract fun action()

  fun registerItem() {
    menuItem = JMenuItem(getLabelName())
    menuItem!!.addActionListener(
      ActionListener {
        try {
          action()
        } catch (e: Exception) {
          log("Error: %s module something happened.", getLabelName())
          errWithStackTrace(e)
        }
      }
    )
  }

  fun setDependentData(hm: HashMap<String, Any>?) {
    this.dependentData = hm
  }

  fun getMenuItem(): JMenuItem? = this.menuItem
}
