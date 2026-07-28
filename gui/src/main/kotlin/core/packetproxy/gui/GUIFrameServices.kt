package packetproxy.gui

import javax.swing.JFrame
import packetproxy.CoreServices
import packetproxy.model.ModelServices

/** Resolves dependencies from the application frame explicitly passed to GUI child components. */
val JFrame.modelServices: ModelServices
  get() = (this as GUIMain).modelServices

val JFrame.coreServices: CoreServices
  get() = (this as GUIMain).coreServices
