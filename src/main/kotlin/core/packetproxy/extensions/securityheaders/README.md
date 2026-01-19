# Security Headers Extension

PacketProxy用のセキュリティヘッダー分析拡張機能です。HTTPレスポンスヘッダーを分析し、セキュリティ上の問題（CSPの欠如、HSTSの不備など）を検出します。

## ルールの追加方法

新しいセキュリティチェックルールを追加するには、以下の手順に従ってください。

### 1. SecurityCheckインターフェースの実装

`packetproxy.extensions.securityheaders.checks` パッケージ内に、`SecurityCheck` インターフェースを実装した新しいクラスを作成します。

実装が必要なメソッド：

* **getName()**: チェックの表示名（Issuesタブで使用）
* **getColumnName()**: 結果テーブルのカラム名
* **getMissingMessage()**: チェック失敗時のエラーメッセージ
* **matchesHeaderLine(String headerLine)**: このチェックが対象とするヘッダー行かどうかを判定（小文字で判定）
* **check(HttpHeader header, Map<String, Object> context)**: チェック処理の本体
  * 戻り値として `SecurityCheckResult.ok()`, `.warn()`, `.fail()` を返します。

オプションで以下のメソッドをオーバーライドして、結果表示のハイライトをカスタマイズできます：

* **getGreenPatterns()**: 安全な設定を示す文字列パターン（リスト）
* **getYellowPatterns()**: 注意が必要な設定を示す文字列パターン（リスト）
* **getRedPatterns()**: 危険な設定を示す文字列パターン（リスト）

実装例：

```java
package packetproxy.extensions.securityheaders.checks;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import packetproxy.extensions.securityheaders.SecurityCheck;
import packetproxy.extensions.securityheaders.SecurityCheckResult;
import packetproxy.http.HttpHeader;

public class MyCustomCheck implements SecurityCheck {

    @Override
    public String getName() {
        return "My Check";
    }

    @Override
    public String getColumnName() {
        return "MyCheck";
    }

    @Override
    public String getMissingMessage() {
        return "My Check header is missing";
    }

    @Override
    public boolean matchesHeaderLine(String headerLine) {
        return headerLine.startsWith("my-header:");
    }

    @Override
    public SecurityCheckResult check(HttpHeader header, Map<String, Object> context) {
        String value = header.getValue("My-Header").orElse("");
        if (value.equals("secure-value")) {
            return SecurityCheckResult.ok(value, value);
        }
        return SecurityCheckResult.fail("Invalid value", value);
    }
}
```

### 2. ルールの登録

`packetproxy.extensions.securityheaders.SecurityHeadersExtension` クラスの `SECURITY_CHECKS` リストに、作成したクラスのインスタンスを追加します。

```java
private static final List<SecurityCheck> SECURITY_CHECKS = Arrays.asList(
    new CspCheck(),
    new XssProtectionCheck(),
    // ...
    new MyCustomCheck() // ここに追加
);
```

### 3. ビルドと実行

プロジェクトを再ビルドし、PacketProxyを起動すると、新しいカラムが追加され、チェックが実行されます。
