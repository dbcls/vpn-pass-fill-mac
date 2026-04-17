# MacOSのFortiClient VPNでパスワード自動で埋める何か

AIで適当に作ったので自己責任で使ってください

```
pip install rumps pyobjc
nohup python forti_pass_fill.py > ~/tmp.log 2>&1 &
```

* メニューバーの足跡アイコンからパスワードをキーチェーンに保存
* メニューバーのFortiClientアイコンから"Conect to hoge"でつなげた時のみ対応
* LaunchAgentで常駐化とかは自分で調べてやってください

## パスワードだけ自動化
* forti_pass_fill.py
* パスワードだけ対応版
* トークンは自分でコピペしてください

## トークンも自動化（Apple mail版）
* forti_pass_fill_applemail.py
* 受信設定済みのApple mailアプリを起動しておく
* メニューバーのアイコンから NIG のメールアカウント名指定
* メール受信を待つので時間がかかる場合もあります

## トークンも自動化（ブラウザの Gmail 版）
* 誰かが作るかもしれない