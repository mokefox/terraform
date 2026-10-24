# 🛡️ Zero-Trust Multi-Layer Security Architecture (OSI Reference Model)

OSI参照モデルおよび多層防御（Defense in Depth）・ゼロトラストセキュリティモデルに基づく包括的なセキュリティ基盤の設計・実装リポジトリです。

---

## 📂 ディレクトリ構成

```text
security-architecture/
├── 01_dns_dnssec/              # L7 (DNS層): DNSSEC / Route53 / CoreDNS DNSSEC検証
│   ├── main.tf                 # Route 53 DNSSEC & Resolver 設定 (Terraform)
│   └── coredns-dnssec.yaml     # Kubernetes CoreDNS DNSSEC & DoT フォワーディング
│
├── 02_waf_edge/                # L7 (エッジ層): AWS WAF v2 & CloudFront
│   ├── waf_web_acl.tf          # WAF (SQLi, XSS, CSRF, Tor/匿名IPブロック, レート制限)
│   └── cloudfront_distribution.tf # CloudFront (TLS 1.3, HSTS, CSP, カスタムヘッダー)
│
├── 03_load_balancer/           # L4/L7 (ロードバランサー層): ALB & Nginx
│   ├── alb_security_policy.tf  # ALB (ELBSecurityPolicy-TLS13-1-2-2021-06, TLS終端)
│   └── nginx.conf              # Nginx (TLS 1.3, PFS暗号, BREACH/CRIME対策, セキュリティヘッダー)
│
├── 04_network_segmentation/    # L3/L4 (ネットワーク層): SG & NetworkPolicy
│   ├── security_groups.tf      # AWS SG (DMZ -> App -> DB の最小ポート・階層化制御)
│   └── network_policy.yaml     # K8s NetworkPolicy (Default Deny & マイクロセグメンテーション)
│
├── 05_container_hardening/     # ホスト/コンテナ層: ランタイム保護・最小権限・封じ込め
│   ├── Dockerfile.hardened     # Multi-stage, Distroless, Non-root (UID: 10001), 攻撃ツール排除
│   ├── pod-security.yaml       # K8s PodSecurityContext (ReadOnly RootFS, Drop ALL Caps, Seccomp)
│   ├── falco-rules.yaml        # Falco ランタイム侵入検知・権限昇格検知・封じ込め
│   └── image-signing-kyverno.yaml # Cosign イメージ署名検証 (Kyverno Policy)
│
└── 06_app_backend/             # L7 (アプリケーション層): 安全な Go 実装
    ├── main.go                 # CSRFトークン (HMAC), XSSサニタイズ, タイムアウト, レート制限
    ├── main_test.go            # セキュリティ機能単体テスト
    └── go.mod
```

---

## 🚀 主なセキュリティ機能と防御メカニズム

1. **DNSSEC による改竄・スプーフィング防止 (DNS層)**
   - KMS管理キーによる権限ゾーンのDNSSEC署名 (`RRSIG`, `DNSKEY`, `DS` レコード)。
   - VPC Resolver および Kubernetes CoreDNS によるDNSSEC検証の強制。

2. **エッジ多層防御 (WAF & CDN層)**
   - AWS WAF Managed Rules: `AWSManagedRulesSQLiRuleSet`, `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesAnonymousIpList` (Tor, 匿名VPN, 不正ホスティングIPを即時遮断)。
   - IPベースのレートリミット (5分間1000req) および CSRF トークン / ヘッダー照合。
   - CloudFront による TLS 1.3 強制、および厳格なセキュリティレスポンスヘッダー (`HSTS`, `CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`) の付与。

3. **ロードバランサー & TLS終端 (LB層)**
   - 最新の TLS 1.3 セキュリティポリシー (`ELBSecurityPolicy-TLS13-1-2-2021-06`) による暗号化終端。脆弱なCBC/3DES/RC4等を排除。
   - ALB への直接アクセスを遮断し、CloudFront からのカスタムシークレットヘッダー (`X-Origin-Verify`) 検証リスナーでのみルーティング。

4. **ネットワークセグメンテーション (SG & NetworkPolicy)**
   - ALB -> App -> DB の厳格な一方向・最小ポート通信許可。
   - Kubernetes における `Default Deny` ポリシーと、Pod間マイクロセグメンテーションによる侵害時の横展開（ラテラルムーブメント）阻止。

5. **コンテナ要塞化・最小権限・ランタイム封じ込め**
   - **Distroless & Non-root**: シェルやパッケージマネージャを含まない最小イメージ、非rootユーザー (`UID: 65532 / 10001`) で実行。
   - **特権昇格防止**: `allowPrivilegeEscalation: false`、`readOnlyRootFilesystem: true`、`capabilities: { drop: ["ALL"] }`。
   - **カーネルサンドボックス**: `seccompProfile: RuntimeDefault`、`AppArmor`。
   - **サプライチェーン保護**: `Cosign` / `Kyverno` による署名検証アドミッション制御。
   - **ランタイム検知 & 封じ込め**: `Falco` (eBPF) による不正シェル起動・特権昇格・不正外向き通信のリアルタイム検知と隔離。
