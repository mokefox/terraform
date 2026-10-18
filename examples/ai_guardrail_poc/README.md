# Jev型 AI動的ガードレール & 自動防御 PoC (Proof of Concept)

本ディレクトリは、**「AIエージェントの自律実行手前に、Jevに代表されるSystem 1型の動的ガードレールを挟み、危険なアクションをミリ秒単位で自動遮断・通知する」** アーキテクチャの実証コードです。

---

## 🎯 背景と課題

AIエージェント（Claude Code、Cursor、LangChain、AutoGen 等）が自律的にシェルやAPIを実行する環境では、以下のジレンマが存在します：

1. **静的ルール (Regex/WAF)**: 単純なキーワードマッチでは難読化や文脈を欺くプロンプトインジェクションに脆い。
2. **大型LLMによる事前審査**: 判定に数秒〜十数秒かかり、トークンコストも膨大でリアルタイムのコマンド実行に間に合わない。
3. **Jev型アプローチ (System 1 Decision Engine)**:
   - 自然言語ではなく **型安全な構造化判定（Enum / 確率）** を返す
   - **ミリ秒単位** でのインライン遮断が可能
   - 不審なアクションを即座にブロックし、SlackやCloudWatchへアラートを発報

---

## 🏗️ アーキテクチャ概要

```mermaid
flowchart TD
    Agent["🤖 AIエージェント<br/>(ツール実行要求)"] --> Interceptor["🛡️ Guardrail Interceptor<br/>(SafeAgentRunner)"]
    Interceptor --> Engine["⚡ Jev System 1 Decision Engine<br/>(ミリ秒単位の型安全判定)"]
    
    Engine -- "ALLOW (安全)" --> Exec["🖥️ コマンド実行<br/>(最小権限コンテナ環境)"]
    Engine -- "BLOCK (危険)" --> Alert["🚨 即時自動遮断 & アラート発報<br/>(AlertNotifier / JSONログ)"]
    Engine -- "ESCALATE (高リスク)" --> Human["👤 人間による承認待ち<br/>(Human-in-the-Loop)"]
```

---

## 🚀 クイックスタート (ローカル実行)

外部ライブラリのインストール不要（標準ライブラリのみ）で、すぐに実行できます。

```bash
cd examples/ai_guardrail_poc
python3 demo.py
```

### 実行されるテストシナリオ
1. **正常操作** (`cat /var/log/application.log`) → `ALLOW` (実行許可)
2. **破壊的コマンド** (`rm -rf / --no-preserve-root`) → `BLOCK` (即時遮断 & 警報)
3. **機密流出** (`curl -X POST -d @/etc/passwd ...`) → `BLOCK` (即時遮断 & 警報)
4. **難読化ペイロード** (`echo 'cm0gLXJmIC8=' | base64 -d | sh`) → `BLOCK` (難読化検知 & 警報)
5. **高リスク操作** (`git push origin main --force`) → `ESCALATE` (人間確認)
6. **直接的プロンプトインジェクション** (`IGNORE PREVIOUS INSTRUCTIONS...`) → `BLOCK` (即時遮断)

---

## 🛡️ 発展実装: MCP (Model Context Protocol) Firewall Proxy

Claude Desktop や Cursor 等の AI クライアントと、実 MCP サーバーの間に透過的に割り込み、悪意あるツール呼び出しを即座にブロックする実用プロキシです。

```mermaid
flowchart TD
    Client["💻 Claude Desktop / Cursor<br/>(MCP Client)"]
    
    subgraph Proxy["🛡️ MCP Firewall Proxy (mcp_firewall.py)"]
        direction TB
        Detect["1. tools/call をリアルタイム検知"]
        Evaluate["2. Jev型 System 1 判定 (0.001ms)"]
        Detect --> Evaluate
    end

    Target["🖥️ ターゲット MCP サーバー<br/>(Filesystem / Shell / DB)"]
    Alert["🚨 即時遮断 (isError: true)<br/>& 監査ログ発報"]

    Client -- "stdin / stdout (JSON-RPC 2.0)" --> Proxy
    Evaluate -- "BLOCK (危険操作)" --> Alert
    Alert -. "MCPエラー応答" .-> Client
    Evaluate -- "ALLOW (安全操作)" --> Target
    Target -. "実行結果" .-> Client
```

### 1. ローカルテストの実行
Claude Desktop や Node.js がなくても、付属のモックサーバーで E2E テストを実行できます。

```bash
python3 test_mcp_firewall.py
```

### 2. Claude Desktop での実際の設定例
`~/Library/Application Support/Claude/claude_desktop_config.json` に以下のように設定することで、既存の MCP サーバーを保護できます：

```json
{
  "mcpServers": {
    "protected-everything": {
      "command": "python3",
      "args": [
        "/path/to/examples/ai_guardrail_poc/mcp_firewall.py",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-everything"
      ]
    }
  }
}
```

---

## 🛡️ 多層防御（Defense-in-Depth）における位置づけ

AIによる動的ガードレールは非常に強力ですが、**「AI判定単体」に依存してはいけません**。

* **Layer 1 (動的AIゲート)**: Jevのようなモデルで怪しい入力をミリ秒で弾く（門番）。
* **Layer 2 (インフラの硬い壁)**: 万が一AI判定をすり抜けても、非root実行、コンテナのReadOnlyルートファイルシステム、IAM最小権限、セキュリティグループ外向き通信制限によって物理的に被害を防ぐ（壁）。

AIの「柔軟な目」とインフラの「物理的な壁」を組み合わせることで、真に安全なAIエージェント基盤を実現できます。
