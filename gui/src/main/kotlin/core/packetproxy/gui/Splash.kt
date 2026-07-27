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

import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JWindow
import javax.swing.SwingUtilities

class Splash {
  private var splashScreen: JWindow? = null

  init {
    createSplash()
  }

  fun show() {
    runAsync { splashScreen?.isVisible = true }
  }

  fun close() {
    runAsync {
      splashScreen?.isVisible = false
      splashScreen = null
    }
  }

  private fun runAsync(runnable: Runnable) {
    if (SwingUtilities.isEventDispatchThread()) {
      runnable.run()
      return
    }
    SwingUtilities.invokeLater(runnable)
  }

  private fun createSplash() {
    var image = ImageIcon(javaClass.getResource("/gui/splash.png"))
    var splashLabel = JLabel(image)
    splashScreen = JWindow(JFrame())
    splashScreen?.contentPane?.add(splashLabel)
    splashScreen?.pack()
    splashScreen?.setLocationRelativeTo(null)
  }
}
