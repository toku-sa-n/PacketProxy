/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import packetproxy.model.ListenPort

class Listen(val listenInfo: ListenPort) {
  private val proxy: Proxy = ProxyFactory.create(listenInfo)

  init {
    proxy.start()
  }

  @Throws(Exception::class)
  fun close() {
    proxy.close()
    DuplexManager.getInstance().closeAndClearDuplex(listenInfo.getPort())
  }
}
