# multiple_proxy
セキュリティ上の関係で「一度HTTPプロキシに接続しないとサーバーに接続できない」みたいな構造にすることがあると思います。
そういう時用のやつです。

## 例
```deno
const conn = proxySocket(["http://xxx.xxx.xxx.xxx:3128/","http://yyy.yyy.yyy.yyy:3128/"], ["zzz.zzz.zzz.zzz", 80]);
```

## 改ざん確認
データの改ざんを確認する場合は `tcpdata.siyukatu.com` をご利用下さい。
