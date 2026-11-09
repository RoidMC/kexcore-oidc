# StormEngine 插件开发指南

StormEngine 的每个 OIDC 端点都是一个独立插件。插件只依赖 `pkg/storm`（以及需要的
`pkg/protocol`、`pkg/storm/shared`），不需要读引擎内部源码就能实现。本文档给出
接口签名、装配方式和常见坑。

## 1. 最小插件

```go
package whoami

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm"
)

type Plugin struct{}

func (p *Plugin) Name() string { return "whoami" }

func (p *Plugin) Register(r chi.Router) {
	r.Get("/plugin/whoami", p.handle)
}

func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"service":"whoami"}`))
}

// New 是工厂函数。返回 nil 表示"放弃注册"（例如缺少存储能力）。
func New(ctx *storm.PluginContext) *Plugin { return &Plugin{} }
```

必须实现 [`storm.Plugin`](../pkg/storm/plugin.go)：

```go
type Plugin interface {
	Name() string
	Register(r chi.Router)
}
```

`Name()` 必须全局唯一：重名不会在注册阶段报错，但会在 `Build()` 的 discovery
冲突检测阶段 panic。

## 2. 把插件装进服务器

引擎只从显式来源收集插件，不存在隐式自动发现。

### 2.1 自建 Engine

```go
engine := storm.New(storage, issuerFn,
	storm.WithMiddleware(shared.IssuerMiddleware(issuerFn)), // 见 §5 坑 2
	storm.WithPlugins(
		append(builtin.All(),
			storm.NamedPluginFactory{
				Name:     "whoami",
				Priority: 1200,
				Factory:  storm.FactoryOf(whoami.New),
			},
		)...,
	),
)
handler := engine.Build()
```

- `WithPlugins` 接收 `NamedPluginFactory`，按 `Priority` 从小到大的顺序注册。
- `WithPlugin` 接收匿名工厂，固定最后注册（priority 9999）。
- 内置优先级常量见 [`engine.go`](../pkg/storm/engine.go) 的 `Priority*`。

### 2.2 使用示例服务器的 SetupTenant（不 fork）

```go
import "github.com/roidmc/kexcore-oidc/v3/example/storm-server/stormsetup"

handler := stormsetup.SetupTenant(stormsetup.TenantConfig{
	Issuer: "https://op.example.com/",
	Plugins: []storm.NamedPluginFactory{
		{Name: "whoami", Priority: 1200, Factory: storm.FactoryOf(whoami.New)},
	},
})
```

`TenantConfig.Plugins` 会追加到 `builtin.All()` 之后。同名插件不会被替换，
而是两个都注册——自定义插件不要复用内置名字。

### 2.3 init() 自注册（全局注册表）

```go
func init() {
	storm.RegisterPlugin("whoami", 1200, storm.FactoryOf(whoami.New))
}
```

`RegisterPlugin` 只写入全局注册表，**`storm.New` 不会自动加载它**。
必须显式传入：

```go
engine := storm.New(storage, issuerFn,
	storm.WithPlugins(storm.RegisteredPlugins()...),
)
```

## 3. 可选扩展接口

| 接口 | 用途 |
|---|---|
| `CategorizablePlugin` | 声明 `Category()`（Core/Standard/Optional）和 `Requires()` 存储能力 |
| `DiscoveryContributor` | 向 `/.well-known/openid-configuration` 贡献字段 |
| `MiddlewareProvider` | 注册作用于全局请求链的中间件 |

### 3.1 贡献 discovery 字段

```go
func (p *Plugin) Contribute(ctx context.Context, cfg *protocol.DiscoveryConfiguration) {
	cfg.Extra["whoami_endpoint"] = shared.EndpointURL(ctx, protocol.NewEndpoint("/plugin/whoami"))
}
```

`ctx` 里的 issuer 来自 `shared.IssuerMiddleware`（见 §5 坑 2）。只写自己拥有的字段，
扩展字段放 `cfg.Extra`。

### 3.2 声明存储能力

```go
func (p *Plugin) Category() storm.PluginCategory { return storm.CategoryStandard }

func (p *Plugin) Requires() []storm.StorageCapability {
	return []storm.StorageCapability{storm.CapTokenStore}
}
```

`Requires()` 在 `Build()` 的 `Validate()` 阶段检查，缺失时返回可读错误并 panic。
它**不会**在工厂执行前预检查；需要软降级的插件应在工厂里自行判断并返回 nil。

### 3.3 类型化工厂

`storm.FactoryOf` 把 `func(*PluginContext) *T` 适配成 `PluginFactory`，并把
`(*T)(nil)` 归一化成真正的 `nil`，这样引擎的"放弃注册"判断才生效。

## 4. 生命周期与错误语义

1. `storm.New` → 调用工厂、过滤 disabled、按 priority 注册路由。
2. 工厂返回 `nil` → 记录 warn 并跳过（Optional 插件常用）。
3. `engine.Build()` → 聚合 discovery、校验 `Requires()`、安装中间件。
4. 校验失败或 discovery 字段冲突 → **panic**（配置错误，启动即失败）。
5. Core 插件（authorization/token/keys/discovery）对必需存储接口做无检查断言，
   缺失时在工厂内直接 panic。

## 5. 实测踩过的坑

1. **`init(){RegisterPlugin}` 不等于注册。** 只做这一步，端点返回 404。
   必须 `WithPlugins(RegisteredPlugins())` 或直接传 `NamedPluginFactory`。
2. **issuer 不会自动进请求上下文。** `New` 只把 `issuerFn` 放进
   `PluginContext.IssuerFn` 和 discovery；要在 handler 里
   `shared.IssuerFromContext(ctx)` 取到值，必须显式
   `WithMiddleware(shared.IssuerMiddleware(issuerFn))`。
3. **存储能力不满足的行为不是"提前检查"，也不是"静默跳过"。** Core 插件会 panic，
   Optional 插件会返回 nil 被跳过。写新插件时先决定自己要哪一种，并在测试里覆盖。
4. **README 之外没有插件文档。** 本文件就是补充；另外 quickstart 需要用
   `github.com/roidmc/kexcore-oidc/v3/...`，示例服务器默认自签 TLS，地址是
   `https://localhost:9998/`。

## 6. 外部模块依赖

外部插件模块只需要依赖引擎包，不需要依赖示例服务器：

```
module example.com/whoami

require github.com/roidmc/kexcore-oidc/v3 v3.x.y
```

```go
import (
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/shared"
)
```

写完用 `go build ./...` 验证；接口签名足够让你在不读 `pkg/storm` 内部实现的情况下
完成编译。
