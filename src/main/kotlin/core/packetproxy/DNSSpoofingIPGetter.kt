/*
 * Copyright 2026 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import packetproxy.gui.GUIOptionPrivateDNS

class DNSSpoofingIPGetter(private val gui: GUIOptionPrivateDNS) {
  fun isAuto(): Boolean = gui.isAutoSpoofing()

  fun get(): String = gui.getSpoofingIP()

  fun get6(): String = gui.getSpoofingIP6()

  fun getInt(): String = gui.getBindInterface()
}
