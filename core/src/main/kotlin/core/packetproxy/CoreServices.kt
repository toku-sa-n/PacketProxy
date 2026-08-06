/*
 * Copyright 2026 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy

import packetproxy.common.EndpointFactory
import packetproxy.common.UniqueID
import packetproxy.controller.InterceptController
import packetproxy.controller.MainWindowController
import packetproxy.controller.PacketsController
import packetproxy.controller.ResendController
import packetproxy.http.Https
import packetproxy.model.ModelServices
import packetproxy.util.Logging
import packetproxy.util.PacketProxyUtility

interface CoreServiceExtension {
  fun initialize(coreServices: CoreServices)
}

/** Owns the application-scoped services implemented by the core module. */
class CoreServices(val modelServices: ModelServices, val logging: Logging) {
  val uniqueId = UniqueID()
  val packetProxyUtility = PacketProxyUtility()
  val https =
    Https(
      modelServices.configs,
      modelServices.servers,
      modelServices.certCacheManager,
      modelServices.clientKeyManager,
    )
  val endpointFactory = EndpointFactory(https, modelServices.resolutions)
  val duplexManager = DuplexManager()
  val encoderManager = EncoderManager(modelServices.packets, uniqueId)
  val vulCheckerManager = VulCheckerManager()
  val duplexPacketHistory = DuplexPacketHistory(uniqueId, encoderManager.packetSummarizer)
  val duplexFactory =
    DuplexFactory(
      modelServices.packets,
      modelServices.servers,
      modelServices.modifications,
      encoderManager,
      { interceptController },
      uniqueId,
      endpointFactory,
      duplexPacketHistory,
    )
  val resendController: ResendController =
    ResendController(encoderManager, duplexManager, duplexFactory)
  val interceptController: InterceptController by lazy {
    InterceptController(
      modelServices.interceptModel,
      modelServices.interceptOptions,
      resendController,
    )
  }
  val packetsController = PacketsController(modelServices.packets)
  val mainWindowController = MainWindowController()
  val ppContextMenuManager = PPContextMenuManager()
  val proxyFactory =
    ProxyFactory(
      duplexFactory,
      duplexManager,
      endpointFactory,
      encoderManager,
      modelServices,
      https,
    )
  val listenPortManager =
    ListenPortManager(
      modelServices.listenPorts,
      modelServices.servers,
      modelServices.sslPassThroughs,
      proxyFactory,
      duplexManager,
    )
  val privateDns =
    PrivateDNS(modelServices.configs, modelServices.servers, modelServices.resolutions)
  val openVPN = OpenVPN(modelServices.openVPNForwardPorts)

  init {
    modelServices.extensions.setExtensionInitializer { extension ->
      (extension as? CoreServiceExtension)?.initialize(this)
    }
  }
}
