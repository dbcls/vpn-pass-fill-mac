# MacOS の FortiClient VPN でパスワード自動で埋める何か

パスワード保存してくれないし、追加でトークン入力を要求してくる場合もあって手間ですね
* AI で適当に作ったので自己責任で

## 使い方

* Requirements

```
pip install rumps pyobjc
```

* Terminal で実行
  * OS 側で Terminal アプリのアクセシビリティの許可が必要

```
nohup python forti_pass_fill.py > ./status.log 2>&1 &
```

* メニューバーの足跡アイコンからパスワードをキーチェーンに保存
* メニューバーの FortiClient アイコンから "Connect to hoge" でつなげた時のみ対応
* LaunchAgent で起動時常駐化とかは自分で調べてやってください
  * Agent にしたら Terminal のアクセシビリティは要らないかも
  * 常時監視してるのでその分のリソースは食います
    * 監視回数変えたかったらコード書き換えてください (コードは0.4秒毎)

## パスワードだけ自動化
* forti_pass_fill.py
* パスワードだけ対応版
* トークンは自分でコピペしてください

## トークンも自動化（Apple mail 版）
* forti_pass_fill_applemail.py
* トークンを受け取るメールアカウント設定済みの Apple mail アプリを起動しておく
  * OS 側で Mail アプリのアクセシビリティの許可が必要
* メニューバーのアイコンからメールアカウント名を指定
* メール受信を待つので時間がかかる場合もあります

## トークンも自動化（ブラウザの Gmail 版）
* 誰かが作るかもしれない