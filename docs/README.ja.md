# VulnDockCustomized

[VulnDock](https://github.com/Saku0512/VulnDock) を **セルフホスト型 Web アプリ** に作り替えたフォークです。Wails デスクトップ版は廃止し、Go の HTTP サーバーと Svelte のブラウザ UI で動かします。

## できること

- 脆弱性報告の作成・編集・検索・ソフト削除（5 日後に物理削除）
- PoC 添付（SQLite BLOB、1 ファイル 50MB まで）
- CVSS 3.1 / 4.0（ベクトルからスコア計算）
- 単一ユーザー（初回セットアップ、Cookie セッション、パスワード変更）
- 旧デスクトップ版データの取り込み（`migrate --from-json`）

暗号化 ZIP バックアップのエクスポート／復元に対応（形式は旧デスクトップ版と互換）。

## 必要環境

- Go 1.26.4+
- Node.js 22+ / npm（フロントビルド用）

## ビルドと起動

```sh
make install
make build
./build/bin/vulndock-customized
```

ブラウザで `http://127.0.0.1:8080` を開き、初回パスワードを設定します。

データの既定場所: `~/.local/share/vulndock-customized/`

## 開発

1. `make build && VULNDOCK_BIND=127.0.0.1:8080 ./build/bin/vulndock-customized`
2. 別ターミナルで `make frontend-dev`（`/api` は 8080 にプロキシ）

## 旧データの移行

```sh
./build/bin/vulndock-customized migrate --from-json
```

未指定時は `~/.config/VulnDock/reports.json` を読みます。DB に既にデータがある場合は `--force`。

## 運用

Tailscale や LAN 内での利用を想定しています。初回セットアップは通常 `VULNDOCK_SETUP_TOKEN`（未設定時は起動ログ）が必要です。同一マシン直アクセスの開発のみ `VULNDOCK_TRUST_LOOPBACK_SETUP=true` でトークン省略可。HTTPS 運用時は `VULNDOCK_SECURE_COOKIES=true` を推奨。詳細は [WEB_SELF_HOST.md](WEB_SELF_HOST.md) と `deploy/vulndock-customized.service` を参照してください。

## 英語 README

[../README.md](../README.md)
