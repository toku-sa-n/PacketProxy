/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.net.BindException
import packetproxy.model.ListenPort
import packetproxy.model.ListenPortRebootHooks
import packetproxy.model.ListenPortRebooter
import packetproxy.model.ListenPorts
import packetproxy.model.PropertyChangeEventType.LISTEN_PORTS
import packetproxy.model.PropertyChangeEventType.SERVERS
import packetproxy.model.Servers
import packetproxy.util.Logging.err
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.Logging.log

class ListenPortManager private constructor() : PropertyChangeListener {
  private val listenMap = HashMap<String, Listen>()
  private val listenPorts = ListenPorts.getInstance()

  init {
    ListenPortRebootHooks.rebooter = ListenPortRebooter { rebootIfHTTPProxyRunning() }
    listenPorts.addPropertyChangeListener(this)
    Servers.getInstance().addPropertyChangeListener(this)
    listenPorts.refresh()
  }

  @Throws(Exception::class)
  fun rebootIfHTTPProxyRunning() {
    for (listenPort in listenPorts.queryEnabledHttpProxis()) {
      val listen = listenMap[listenPort.getProtoPort()] ?: continue
      listen.close()
      listenMap[listenPort.getProtoPort()] = Listen(listenPort)
    }
  }

  override fun propertyChange(event: PropertyChangeEvent) {
    when {
      LISTEN_PORTS.matches(event) -> {
        try {
          synchronized(listenMap) {
            stopIfRunning()
            startIfStateChanged()
          }
        } catch (exception: Exception) {
          errWithStackTrace(exception)
        }
      }
      SERVERS.matches(event) -> {
        try {
          synchronized(listenMap) { restartAffectedForwarders() }
        } catch (exception: Exception) {
          errWithStackTrace(exception)
        }
      }
    }
  }

  @Throws(Exception::class)
  private fun stopIfRunning() {
    val enabledPorts = listenPorts.queryEnabled().map { it.getProtoPort() }.toSet()
    val iterator = listenMap.iterator()
    while (iterator.hasNext()) {
      val (protoPort, listen) = iterator.next()
      if (protoPort !in enabledPorts) {
        listen.close()
        iterator.remove()
      }
    }
  }

  @Throws(Exception::class)
  private fun startListen(listenPort: ListenPort) {
    try {
      val listen = listenMap[listenPort.getProtoPort()]
      if (listen != null) {
        if (listen.listenInfo != listenPort) {
          listen.close()
          listenMap[listenPort.getProtoPort()] = Listen(listenPort)
          log("## restart: %s", listenPort.getProtoPort())
        }
        return
      }
      log("## start: %s", listenPort.getProtoPort())
      listenMap[listenPort.getProtoPort()] = Listen(listenPort)
    } catch (exception: BindException) {
      err("cannot listen port. (permission issue or already listened)")
      listenPort.setDisabled()
      listenPorts.update(listenPort)
    }
  }

  @Throws(Exception::class)
  private fun startIfStateChanged() {
    for (listenPort in listenPorts.queryEnabled()) {
      startListen(listenPort)
    }
  }

  @Throws(Exception::class)
  private fun restartAffectedForwarders() {
    for (listenPort in listenPorts.queryEnabled()) {
      if (listenPort.getType()?.isForwarder() != true) continue
      val listen = listenMap[listenPort.getProtoPort()] ?: continue
      log("## restarting forwarder due to server change: %s", listenPort.getProtoPort())
      listen.close()
      listenMap[listenPort.getProtoPort()] = Listen(listenPort)
    }
  }

  companion object {
    private var instance: ListenPortManager? = null

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): ListenPortManager {
      if (instance == null) instance = ListenPortManager()
      return instance!!
    }
  }
}
