# SBON

SBONは、調達・品質保証・セキュリティ管理・規制対応など、非エンジニアのSBOM利用者を想定した日本語ファーストのSBOM Viewerです。

## 使い方

`index.html` をブラウザで開きます。

- CycloneDX JSON / SPDX JSON の読み込み
- コンポーネント一覧、依存関係、詳細説明の表示
- 暗号、ネットワーク、認証、OS基盤、更新機構の観点で分類
- 脆弱性、EOL可能性、ライセンス未確認などのリスク表示
- PDF出力はブラウザの印刷機能を使用
- CSV出力はExcelで開けるUTF-8 BOM付きCSV

## ファイル

- `index.html`: 画面構造
- `styles.css`: UIスタイル
- `app.js`: SBOM解析、リスク判定、表示、出力処理
- `mvp.md`: MVPコンセプト
