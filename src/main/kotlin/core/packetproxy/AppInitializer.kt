package packetproxy

import java.nio.file.Paths
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import kotlin.system.exitProcess
import packetproxy.common.ClientKeyManager
import packetproxy.common.ConfigIO
import packetproxy.common.FontManager
import packetproxy.common.Utils
import packetproxy.controller.InterceptController
import packetproxy.gui.GUIMain
import packetproxy.model.CharSets
import packetproxy.model.ClientCertificates
import packetproxy.model.Configs
import packetproxy.model.Database
import packetproxy.model.Diff
import packetproxy.model.DiffBinary
import packetproxy.model.DiffJson
import packetproxy.model.Extensions
import packetproxy.model.Filters
import packetproxy.model.InterceptOptions
import packetproxy.model.ListenPorts
import packetproxy.model.Modifications
import packetproxy.model.Packets
import packetproxy.model.ResenderPackets
import packetproxy.model.Resolutions
import packetproxy.model.SSLPassThroughs
import packetproxy.model.Servers
import packetproxy.util.CharSetUtility
import packetproxy.util.err
import packetproxy.util.errWithStackTrace
import packetproxy.util.init
import packetproxy.util.log

class AppInitializer {
  private var isGulp = false
  private var settingsPath = ""
  private var certCacheManager: CertCacheManager? = null
  private var clientCertificates: ClientCertificates? = null
  private var charSets: CharSets? = null
  private var charSetUtility: CharSetUtility? = null
  private var configs: Configs? = null
  private var diff: Diff? = null
  private var diffBinary: DiffBinary? = null
  private var diffJson: DiffJson? = null
  private var database: Database? = null
  private var extensions: Extensions? = null
  private var filters: Filters? = null
  private var duplexManager: DuplexManager? = null
  private var encoderManager: EncoderManager? = null
  private var fontManager: FontManager? = null
  private var guiMain: GUIMain? = null
  private var interceptOptions: InterceptOptions? = null
  private var interceptController: InterceptController? = null
  private var listenPortManager: ListenPortManager? = null
  private var listenPorts: ListenPorts? = null
  private var modifications: Modifications? = null
  private var packets: Packets? = null
  private var resenderPackets: ResenderPackets? = null
  private var resolutions: Resolutions? = null
  private var servers: Servers? = null
  private var sslPassThroughs: SSLPassThroughs? = null
  private var vulCheckerManager: VulCheckerManager? = null

  private var isCoreNotReady = true
  private var isGulpNotReady = true
  private var isComponentsNotReady = true

  private fun setArgsInternal(isGulp: Boolean, settingsPath: String?) {
    this.isGulp = isGulp
    this.settingsPath = settingsPath ?: ""
  }

  private fun initCoreInternal() {
    check(isCoreNotReady) { "initCore() has already been done !" }

    try {
      init(isGulp)
    } catch (e: Exception) {
      System.err.println("[FATAL ERROR]: Logging.init(), exit 1")
      System.err.println(e.message)
      e.printStackTrace(System.err)
      exitProcess(1)
    }

    log("Launching PacketProxy !")
    isCoreNotReady = false
  }

  private fun initGulpInternal() {
    check(isGulp) { "initGulp() is for gulp mode only !" }
    check(isGulpNotReady) { "initGulp() has already been done !" }

    initDatabase()
    initPackets()
    isGulpNotReady = false
  }

  private fun initDatabase() {
    val dbPath =
      Paths.get(System.getProperty("user.home"), ".packetproxy", "db", "resources.sqlite3")
    getDatabaseInternal().openAt(dbPath.toString())
    log("Databaseを初期化しました: $dbPath")
  }

  private fun initPackets() {
    getPacketsInternal(false)
    log("Packetsを初期化しました")
  }

  private fun initComponentsInternal() {
    check(isComponentsNotReady) { "initComponents() has already been done !" }

    val dbDependentFuture1 = CompletableFuture.runAsync { initClientKeyManager() }
    val dbDependentFuture2 = CompletableFuture.runAsync { initListenPortManager() }
    val independentFuture1 = CompletableFuture.runAsync { initEncoderManager() }
    val independentFuture2 = CompletableFuture.runAsync { initVulCheckerManager() }

    try {
      CompletableFuture.allOf(
          dbDependentFuture1,
          dbDependentFuture2,
          independentFuture1,
          independentFuture2,
        )
        .get()
      log("全てのコンポーネントの初期化が完了しました")
    } catch (e: ExecutionException) {
      val cause = e.cause
      if (cause is Exception) {
        errWithStackTrace(cause)
        throw cause
      }
      errWithStackTrace(e)
      throw e
    } catch (e: InterruptedException) {
      errWithStackTrace(e)
      Thread.currentThread().interrupt()
      throw RuntimeException("初期化が中断されました", e)
    }

    loadSettingsFromJson()
    isComponentsNotReady = false
  }

  private fun initClientKeyManager() {
    ClientKeyManager.initialize()
    log("ClientKeyManagerを初期化しました")
  }

  private fun initListenPortManager() {
    getListenPortManagerInternal()
    log("ListenPortManagerを初期化しました")
  }

  private fun getCertCacheManagerInternal(): CertCacheManager =
    certCacheManager ?: CertCacheManager().also { certCacheManager = it }

  private fun clearCertCacheInternal() {
    certCacheManager?.clearCacheEntries()
  }

  private fun getClientCertificatesInternal(): ClientCertificates =
    clientCertificates ?: ClientCertificates().also { clientCertificates = it }

  private fun getConfigsInternal(): Configs = configs ?: Configs().also { configs = it }

  private fun clearConfigsInternal() {
    configs = null
  }

  private fun getCharSetsInternal(): CharSets = charSets ?: CharSets().also { charSets = it }

  private fun getCharSetUtilityInternal(): CharSetUtility =
    charSetUtility ?: CharSetUtility().also { charSetUtility = it }

  private fun getDiffInternal(): Diff = diff ?: Diff().also { diff = it }

  private fun getDiffBinaryInternal(): DiffBinary =
    diffBinary ?: DiffBinary().also { diffBinary = it }

  private fun getDiffJsonInternal(): DiffJson = diffJson ?: DiffJson().also { diffJson = it }

  private fun getDatabaseInternal(): Database = database ?: Database().also { database = it }

  private fun getExtensionsInternal(): Extensions =
    extensions ?: Extensions().also { extensions = it }

  private fun getFiltersInternal(): Filters = filters ?: Filters().also { filters = it }

  private fun getInterceptOptionsInternal(): InterceptOptions =
    interceptOptions ?: InterceptOptions().also { interceptOptions = it }

  private fun getFontManagerInternal(): FontManager =
    fontManager ?: FontManager().also { fontManager = it }

  private fun setGuiMainInternal(guiMain: GUIMain) {
    this.guiMain = guiMain
  }

  private fun getGuiMainInternal(): GUIMain =
    guiMain ?: throw Exception("GUIMain instance not found.")

  private fun getDuplexManagerInternal(): DuplexManager =
    duplexManager ?: DuplexManager().also { duplexManager = it }

  private fun getInterceptControllerInternal(): InterceptController =
    interceptController ?: InterceptController().also { interceptController = it }

  private fun getListenPortManagerInternal(): ListenPortManager =
    listenPortManager ?: ListenPortManager().also { listenPortManager = it }

  private fun getListenPortsInternal(): ListenPorts =
    listenPorts ?: ListenPorts().also { listenPorts = it }

  private fun getModificationsInternal(): Modifications =
    modifications ?: Modifications().also { modifications = it }

  private fun getPacketsInternal(restore: Boolean): Packets =
    packets ?: Packets(restore).also { packets = it }

  private fun getPacketsInternal(): Packets =
    packets ?: throw Exception("Packets インスタンスが作成されていません。")

  private fun getResenderPacketsInternal(): ResenderPackets =
    resenderPackets ?: ResenderPackets().also { resenderPackets = it }

  private fun getResolutionsInternal(): Resolutions =
    resolutions ?: Resolutions().also { resolutions = it }

  private fun getServersInternal(): Servers = servers ?: Servers().also { servers = it }

  private fun getSSLPassThroughsInternal(): SSLPassThroughs =
    sslPassThroughs ?: SSLPassThroughs().also { sslPassThroughs = it }

  private fun initEncoderManager() {
    getEncoderManagerInternal()
    log("EncoderManagerを初期化しました")
  }

  private fun getEncoderManagerInternal(): EncoderManager =
    encoderManager ?: EncoderManager().also { encoderManager = it }

  private fun initVulCheckerManager() {
    getVulCheckerManagerInternal()
    log("VulCheckerManagerを初期化しました")
  }

  private fun getVulCheckerManagerInternal(): VulCheckerManager =
    vulCheckerManager ?: VulCheckerManager().also { vulCheckerManager = it }

  private fun loadSettingsFromJson() {
    if (settingsPath.isEmpty()) return

    try {
      val jsonBytes = Utils.readfile(settingsPath)
      val json = String(jsonBytes, Charsets.UTF_8)
      val configIO = ConfigIO()
      configIO.setOptions(json)
      log("設定ファイルを正常に読み込みました: $settingsPath")
    } catch (e: Exception) {
      err("設定ファイルの読み込みに失敗しました: ${e.message}", e)
      errWithStackTrace(e)
    }
  }

  companion object {
    private lateinit var current: AppInitializer

    @JvmStatic
    fun bootstrap(appInitializer: AppInitializer = AppInitializer()): AppInitializer {
      current = appInitializer
      return current
    }

    @JvmStatic fun bootstrap(): AppInitializer = bootstrap(AppInitializer())

    private fun currentInstance(): AppInitializer {
      check(::current.isInitialized) { "AppInitializer has not been bootstrapped." }
      return current
    }

    @JvmStatic
    fun setArgs(isGulp: Boolean, settingsPath: String?) =
      currentInstance().setArgsInternal(isGulp, settingsPath)

    @JvmStatic fun initCore() = currentInstance().initCoreInternal()

    @JvmStatic fun initGulp() = currentInstance().initGulpInternal()

    @JvmStatic fun initComponents() = currentInstance().initComponentsInternal()

    @JvmStatic
    fun getCertCacheManager(): CertCacheManager = currentInstance().getCertCacheManagerInternal()

    @JvmStatic fun clearCertCache() = currentInstance().clearCertCacheInternal()

    @JvmStatic
    fun getClientCertificates(): ClientCertificates =
      currentInstance().getClientCertificatesInternal()

    @JvmStatic fun getConfigs(): Configs = currentInstance().getConfigsInternal()

    @JvmStatic fun clearConfigs() = currentInstance().clearConfigsInternal()

    @JvmStatic fun getCharSets(): CharSets = currentInstance().getCharSetsInternal()

    @JvmStatic
    fun getCharSetUtility(): CharSetUtility = currentInstance().getCharSetUtilityInternal()

    @JvmStatic fun getDiff(): Diff = currentInstance().getDiffInternal()

    @JvmStatic fun getDiffBinary(): DiffBinary = currentInstance().getDiffBinaryInternal()

    @JvmStatic fun getDiffJson(): DiffJson = currentInstance().getDiffJsonInternal()

    @JvmStatic fun getDatabase(): Database = currentInstance().getDatabaseInternal()

    @JvmStatic fun getExtensions(): Extensions = currentInstance().getExtensionsInternal()

    @JvmStatic fun getFilters(): Filters = currentInstance().getFiltersInternal()

    @JvmStatic
    fun getInterceptOptions(): InterceptOptions = currentInstance().getInterceptOptionsInternal()

    @JvmStatic fun getFontManager(): FontManager = currentInstance().getFontManagerInternal()

    @JvmStatic fun setGuiMain(guiMain: GUIMain) = currentInstance().setGuiMainInternal(guiMain)

    @JvmStatic fun getGuiMain(): GUIMain = currentInstance().getGuiMainInternal()

    @JvmStatic fun getDuplexManager(): DuplexManager = currentInstance().getDuplexManagerInternal()

    @JvmStatic
    fun getInterceptController(): InterceptController =
      currentInstance().getInterceptControllerInternal()

    @JvmStatic
    fun getListenPortManager(): ListenPortManager = currentInstance().getListenPortManagerInternal()

    @JvmStatic fun getListenPorts(): ListenPorts = currentInstance().getListenPortsInternal()

    @JvmStatic fun getModifications(): Modifications = currentInstance().getModificationsInternal()

    @JvmStatic
    fun getPackets(restore: Boolean): Packets = currentInstance().getPacketsInternal(restore)

    @JvmStatic fun getPackets(): Packets = currentInstance().getPacketsInternal()

    @JvmStatic
    fun getResenderPackets(): ResenderPackets = currentInstance().getResenderPacketsInternal()

    @JvmStatic fun getResolutions(): Resolutions = currentInstance().getResolutionsInternal()

    @JvmStatic fun getServers(): Servers = currentInstance().getServersInternal()

    @JvmStatic
    fun getSSLPassThroughs(): SSLPassThroughs = currentInstance().getSSLPassThroughsInternal()

    @JvmStatic
    fun getEncoderManager(): EncoderManager = currentInstance().getEncoderManagerInternal()

    @JvmStatic
    fun getVulCheckerManager(): VulCheckerManager = currentInstance().getVulCheckerManagerInternal()
  }
}
