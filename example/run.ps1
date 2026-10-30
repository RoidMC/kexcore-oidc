$env:CLIENT_ID="web"
$env:CLIENT_SECRET="secret"
$env:ISSUER="https://192.168.2.133:9998"
$env:SCOPES="openid profile"
$env:PORT=9999
$env:INSECURE_TLS="true"
go run github.com/roidmc/kexcore-oidc/v3/example/client/app