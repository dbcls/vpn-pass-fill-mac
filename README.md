# MacOS の FortiClient VPN でパスワード自動で埋める何か

AI で適当に作ったので自己責任で

## 使い方

```
pip install rumps pyobjc
nohup python forti_pass_fill.py > ./status.log 2>&1 &
```

* メニューバーの足跡アイコンからパスワードをキーチェーンに保存
  * OS 側で Terminal アプリのアクセシビリティの許可が必要
* メニューバーの FortiClient アイコンから "Conect to hoge" でつなげた時のみ対応
* LaunchAgent で起動時常駐化とかは自分で調べてやってください
  * Agent にしたら Terminal のアクセシビリティは要らないかも

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