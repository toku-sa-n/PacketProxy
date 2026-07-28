package packetproxy

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import kotlin.system.exitProcess
import packetproxy.common.ConfigIO
import packetproxy.common.Utils
import packetproxy.extensions.PresetExtensions
import packetproxy.model.Database
import packetproxy.model.ModelServices
import packetproxy.util.Logging

/**
 * アプリケーション起動時のサービスを所有する。
 *
 * モジュール境界: AppInitializer は model/core/gui の個別リポジトリを import せず、モデルの 構成境界となる [Database] と
 * [ModelServices] だけに依存する。プロジェクトの切替時はサービスを 再作成せず、[switchProject] により `Database.openAt(path)`
 * を呼び出し、既存リポジトリが `PropertyChange` の `RECONNECT` を処理する。
 *
 * シングルトン削除の確認:
 * - `rg 'fun getInstance' --glob '**'/'src/**/*.kt'`
 * - `rg '^object ' --glob '**'/'src/main/**/*.kt'`
 */
class AppInitializer private constructor() {
  private var isGulp = false // Gulp modeか否か
  private var settingsPath = "" // 設定用JSONのファイルpath
  val logging = Logging().also { Logging.installFallback(it) }
  private var modelServices: ModelServices? = null
  private var coreServices: CoreServices? = null

  private var isCoreNotReady = true
  private var isGulpNotReady = true
  private var isComponentsNotReady = true

  fun setArgs(isGulp: Boolean, settingsPath: String?) {
    this.isGulp = isGulp
    this.settingsPath = settingsPath ?: ""
  }

  /**
   * Creates long-lived model services. Project changes must use [switchProject] instead.
   *
   * When [dbPath] is null, [ModelServices] creates the database at its default location.
   */
  fun createModelServices(dbPath: String?, restorePackets: Boolean): ModelServices {
    check(modelServices == null) { "ModelServices has already been created." }

    val services = ModelServices(Database(), restorePackets)
    if (dbPath != null) {
      services.database.openAt(dbPath)
    }
    ModelServices.install(services)
    modelServices = services
    coreServices = CoreServices(services, logging)
    logging.logInternal("Databaseを初期化しました: ${services.database.getDatabasePath()}")
    return services
  }

  /** Opens a new project database while retaining all long-lived model services. */
  fun switchProject(path: String) {
    requireModelServices().database.openAt(path)
  }

  /** GUI / CLI(Gulp) に関連なく最初に実行するべき初期化を一度のみ実行する */
  fun initCore() {
    check(isCoreNotReady) { "initCore() has already been done !" }
    // ログ機能のエラーについては標準エラー出力への出力を行い終了する
    try {
      logging.initInternal(isGulp)
    } catch (e: Exception) {
      System.err.println("[FATAL ERROR]: Logging.init(), exit 1")
      System.err.println(e.message)
      e.printStackTrace(System.err)

      exitProcess(1)
    }

    PresetExtensions().registerAll()

    logging.logInternal("Launching PacketProxy !")

    isCoreNotReady = false
  }

  /** CLI(Gulp) 専用の初期化を実行 GUI ではGUIMainなどで実行されている処理 */
  fun initGulp() {
    check(isGulp) { "initGulp() is for gulp mode only !" }
    check(isGulpNotReady) { "initGulp() has already been done !" }
    requireModelServices()

    isGulpNotReady = false
  }

  /**
   * GUI / CLI(Gulp) に共通の初期化を GUI の表示よりも後回しして良い初期化を一度のみ実行する
   *
   * 並列処理による高速化:
   * - EncoderManagerとVulCheckerManagerは完全に独立しているため、並列実行可能
   * - ClientKeyManagerとListenPortManagerはDatabaseに依存しているが、
   *   Databaseは既に初期化済み（GUIモードではstartGUI()で、CLIモードではinitGulp()で初期化）
   *   かつ、それぞれ異なるテーブル（ClientCertificates/Servers/ListenPorts）にアクセスするため、 読み取り操作のみであれば並列実行可能
   *
   * 依存関係の整理:
   * 1. ClientKeyManager: ClientCertificates → Database (読み取りのみ)
   * 2. ListenPortManager: ListenPorts + Servers → Database (読み取りのみ)
   * 3. EncoderManager: クラスパス/JARファイルのスキャン（Database非依存）
   * 4. VulCheckerManager: クラスパスのスキャン（Database非依存）
   */
  fun initComponents() {
    check(isComponentsNotReady) { "initComponents() has already been done !" }

    // Database依存のコンポーネントを並列実行
    // 注意: Databaseは既に初期化済みであることを前提とする
    val dbDependentFuture1 = CompletableFuture.runAsync { initClientKeyManager() }

    val dbDependentFuture2 = CompletableFuture.runAsync { initListenPortManager() }

    val dbDependentFuture3 = CompletableFuture.runAsync { initSessionProfiles() }

    // Database非依存のコンポーネントを並列実行
    val independentFuture1 =
      CompletableFuture.runAsync {
        // encoderのロードに1,2秒かかるのでここでロードをしておく（ここでしておかないと通信がacceptされたタイミングでロードする）
        initEncoderManager()
      }

    val independentFuture2 = CompletableFuture.runAsync { initVulCheckerManager() }

    // 全ての初期化が完了するまで待機
    try {
      CompletableFuture.allOf(
          dbDependentFuture1,
          dbDependentFuture2,
          dbDependentFuture3,
          independentFuture1,
          independentFuture2,
        )
        .get()

      logging.logInternal("全てのコンポーネントの初期化が完了しました")
    } catch (e: ExecutionException) {
      // ExecutionExceptionは、CompletableFuture内で発生した例外をラップした例外
      // e.causeで実際の例外を取得できる
      val cause = e.cause
      if (cause is Exception) {
        logging.errWithStackTraceInternal(cause)
        throw cause
      } else {
        logging.errWithStackTraceInternal(e)
        throw e
      }
    } catch (e: InterruptedException) {
      logging.errWithStackTraceInternal(e)
      Thread.currentThread().interrupt()
      throw RuntimeException("初期化が中断されました", e)
    }

    loadSettingsFromJson()

    isComponentsNotReady = false
  }

  private fun initClientKeyManager() {
    val models = requireModelServices()
    models.clientKeyManager.initialize(models.clientCertificates, models.database)
    logging.logInternal("ClientKeyManagerを初期化しました")
  }

  private fun initListenPortManager() {
    requireCoreServices().listenPortManager
    logging.logInternal("ListenPortManagerを初期化しました")
  }

  private fun initSessionProfiles() {
    requireModelServices().sessionProfiles
    logging.logInternal("SessionProfilesを初期化しました")
  }

  private fun initEncoderManager() {
    requireCoreServices().encoderManager
    logging.logInternal("EncoderManagerを初期化しました")
  }

  private fun initVulCheckerManager() {
    requireCoreServices().vulCheckerManager
    logging.logInternal("VulCheckerManagerを初期化しました")
  }

  /** JSON設定ファイルを読み込んで適用 ListenPortManager初期化後に呼び出すことで、設定ファイル内の有効なプロキシが自動的に開始される */
  private fun loadSettingsFromJson() {
    if (settingsPath.isEmpty()) return

    try {
      val jsonBytes = Utils.readfile(settingsPath)
      val json = String(jsonBytes, Charsets.UTF_8)

      val modelServices = requireModelServices()
      val configIO =
        ConfigIO(
          modelServices.database,
          modelServices.listenPorts,
          modelServices.servers,
          modelServices.modifications,
          modelServices.sslPassThroughs,
        )
      configIO.setOptions(json)

      logging.logInternal("設定ファイルを正常に読み込みました: $settingsPath")
    } catch (e: Exception) {
      logging.errInternal("設定ファイルの読み込みに失敗しました: ${e.message}", e)
      logging.errWithStackTraceInternal(e)
    }
  }

  fun requireModelServices(): ModelServices =
    checkNotNull(modelServices) { "createModelServices() must be called before this operation." }

  fun requireCoreServices(): CoreServices =
    checkNotNull(coreServices) { "createModelServices() must be called before this operation." }

  companion object {
    fun bootstrap(): AppInitializer = AppInitializer()
  }
}
