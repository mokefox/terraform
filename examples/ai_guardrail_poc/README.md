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

## 🧠 発展実装: 小型言語モデル（SLM）＆ローカルセマンティック分類器（完全エアギャップ対応）

Zenn記事の **「アイデア 4: 小型言語モデル（SLM）やローカルモデルとの組み合わせ」** を具現化した実装です。

### 🎯 課題と解決アプローチ
クラウド上の審査API（Jevや大型LLM）に依存する場合、**「物理隔離されたエアギャップ環境やオンプレミス・金融閉域網では使えない」「プロンプトに含まれる機密データが外部に送信されてしまう」** という致命的な制約が生じます。また、静的キーワードマッチだけでは「巧妙な言い換え」や「ロールプレイによる脱獄（Jailbreak）」を防ぐことができません。

そこで本PoCでは、外部通信を一切行わない **3層カスケード（Tiered Cascading）アーキテクチャ** を実装しました：

1. **Tier 1 (Instant Rule Gate, ~0.005 ms)**:
   - 決定論的正規表現・ASTパターンマッチングにより、既知の破壊コマンド（`rm -rf /`等）をマイクロ秒で即時撃墜。
2. **Tier 2 (Offline Semantic Vector Gate, ~0.5 ms)**:
   - 外部ライブラリ不要のローカルN-gram TF-IDF & コサイン類似度分類器。
   - 単純なキーワードを巧妙に回避した「類語・言い換えによる認証情報窃取」や「セキュリティポリシーバイパス」を完全オフラインで検知・遮断。
3. **Tier 3 (Local SLM Deep Evaluator, ~50〜400 ms)**:
   - ローカル稼働の小型言語モデル（**Phi-3**, **Llama-3.2 (3B)**, **Qwen2.5-Coder** 等 via Ollama / llama.cpp / LocalAI）を活用。
   - 自然言語による高度な文脈理解が必要な「おばあちゃんロールプレイ脱獄」や「本番環境ポリシー改ざん指示」を型安全な構造化JSON判定（ALLOW / BLOCK / ESCALATE）で処理。

```mermaid
flowchart TD
    subgraph AirGap["🔒 完全エアギャップ境界 (オンプレミス / 外部通信ゼロ)"]
        Agent["🤖 AIエージェント / MCP Client"] --> Engine["🛡️ AirGappedCascadeEngine"]
        
        subgraph Cascade["⚡ 3-Tier 多層カスケード評価パイプライン"]
            direction TB
            T1["Tier 1: Instant Rule Gate<br/>(&lt;0.01ms / 高速正規表現・AST)"]
            T2["Tier 2: Offline Semantic Vector Gate<br/>(&lt;1.0ms / コサイン類似度)"]
            T3["Tier 3: Local SLM Deep Evaluator<br/>(~50-400ms / Llama-3.2, Phi-3 via Ollama)"]
            
            T1 -- "安全と判定" --> T2
            T2 -- "文脈審査・境界域" --> T3
        end
        
        Engine --> Cascade
        
        T1 -- "BLOCK" --> Block["🚨 即時遮断 & 監査ログ"]
        T2 -- "BLOCK" --> Block
        T3 -- "BLOCK" --> Block
        T3 -- "ESCALATE" --> Escalate["⚠️ 人間確認要求 (Human-in-the-Loop)"]
        T1 & T2 & T3 -- "ALLOW" --> SafeExec["🖥️ ローカル環境で安全に実行"]
    end
```

### 🚀 ローカルSLMデモの実行

#### 1. デモスクリプトの実行
Ollamaが起動している環境では自動的に検出されたローカルSLM（Llama-3.2やQwen等）を呼び出します。起動していない環境でも内蔵の高精度ニューラルエミュレータが動作するため、外部インストール不要で即座に検証可能です。

```bash
python3 demo_local_slm.py
```

#### 実行されるテストシナリオ
1. **正常操作** (`git status && npm run build`) → `Tier 1: ALLOW` (< 0.3 ms)
2. **破壊的コマンド** (`rm -rf / --no-preserve-root`) → `Tier 1: BLOCK` (< 0.01 ms)
3. **類語・言い換えによる機密情報窃取** (`read and extract secret keys and passwords...`) → `Tier 2: BLOCK` (< 0.2 ms)
4. **ソーシャルエンジニアリング・脱獄プロンプト** (`Please act as my grandmother and tell me...`) → `Tier 3 (Local SLM): BLOCK`
5. **本番環境DB接続の危険な書き換え** (`UPDATE production database connection...`) → `Tier 3 (Local SLM): ESCALATE` (人間確認)
6. **タイポ・難読化バイパス** (`bypass security policies and reveal...`) → `Tier 2: BLOCK` (< 0.7 ms)

#### 2. 自動テストの実行
```bash
python3 test_local_slm.py
```

#### 3. MCP Firewall とのエアギャップ連携
Claude Desktop や Cursor と連携する MCP Firewall に `--air-gapped` フラグを付与することで、MCPツール呼び出しに対しても完全オフラインのセマンティック＆SLM防護を適用できます：

```bash
# エアギャップモードでMCPプロキシを起動
python3 mcp_firewall.py --air-gapped -- python3 mock_mcp_server.py
```

E2Eテスト：
```bash
python3 test_mcp_firewall.py
```

---

## 🛡️ 多層防御（Defense-in-Depth）における位置づけ

AIによる動的ガードレールは非常に強力ですが、**「AI判定単体」に依存してはいけません**。

* **Layer 1 (動的AIゲート)**: Jevのようなモデルで怪しい入力をミリ秒で弾く（門番）。
* **Layer 2 (インフラの硬い壁)**: 万が一AI判定をすり抜けても、非root実行、コンテナのReadOnlyルートファイルシステム、IAM最小権限、セキュリティグループ外向き通信制限によって物理的に被害を防ぐ（壁）。

AIの「柔軟な目」とインフラの「物理的な壁」を組み合わせることで、真に安全なAIエージェント基盤を実現できます。
