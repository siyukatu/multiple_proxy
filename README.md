# multiple_proxy
セキュリティ上の関係で「一度HTTPプロキシに接続しないとサーバーに接続できない」みたいな構造にすることがあると思います。
そういう時用のやつです。

## 例
ファイアウォールの内容は以下とします。
- zzz.zzz.zzz.zzzがyyy.yyy.yyy.yyyからのみ接続を受け付けている
- yyy.yyy.yyy.yyyがxxx.xxx.xxx.xxxからのみ接続を受け付けている
```deno
const conn = await proxySocket(["http://xxx.xxx.xxx.xxx:3128/","http://yyy.yyy.yyy.yyy:3128/"], ["zzz.zzz.zzz.zzz", 80]);
```

## 改ざん確認
データの改ざんを確認する場合は `tcpdata.siyukatu.com` (72.14.188.245) をご利用下さい。

# 認証付きプロキシ
今のところ非対応です。
そのうち対応するかもしれません。