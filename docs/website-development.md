# 官网开发、内容维护与部署

官网位于 `apps/web`，公开文档内容位于 `docs/site`。Cargo 继续管理 `crates`、`xtask` 与 Rust 锁文件；pnpm 管理前端 workspace 与 `pnpm-lock.yaml`。网站与 Rust 二进制独立构建和发布，不需要移动原有 Cargo 项目。

架构基于 React 19.2、TypeScript strict、Vite 8、TanStack Start/Router、Tailwind CSS 4.3、Fumadocs 和 react-i18next。Cloudflare Workers 从构建时打包的内容生成 HTML；静态资源包含浏览器脚本、CSS、图片和搜索索引。没有用户数据库、账号、业务 API、分析追踪或后台内容写入。Manifest 提供应用元数据，不代表已有离线缓存；首期没有 Service Worker。

## 命令与质量闸门

使用 Node 24.18.1、pnpm 9.11.0，在仓库根目录执行：

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

完整验证顺序：

```sh
pnpm build
pnpm --filter @umbra/web run licenses
pnpm check
pnpm test
pnpm --filter @umbra/web exec playwright install chromium
pnpm test:e2e
pnpm preview
```

首次构建会生成文件路由类型、公开文章清单、搜索文件和发布信息。`pnpm check` 检查内容、类型和 lint；`pnpm test` 对手写的应用逻辑、组件与内容工具执行至少 90% 行覆盖率闸门；Playwright 检查浏览器交互及直接请求的 SSR 结果。CI 通过 `playwright install --with-deps chromium` 安装系统依赖。浏览器测试不需要 Cloudflare 生产凭据。

现有 `cargo xtask ci`、`cargo xtask coverage` 与 `.github/workflows/ci.yml` 的 Rust 闸门独立保留。前端覆盖率与 Rust 覆盖率不混算。

前端完整依赖树的许可证门禁和锁定直接依赖用途见[依赖与许可证记录](website-dependencies.md)。

## 语言与页面路径

正式源站为 `https://umbra.cat`。所有语言都使用目录前缀，并统一保留末尾斜杠：

| URL / 内容目录 | HTML 语言标签 | 语言 |
| --- | --- | --- |
| `zh-hans` | `zh-Hans` | 简体中文 |
| `zh-hant` | `zh-Hant` | 繁體中文 |
| `en` | `en` | English |
| `fr` | `fr` | Français |
| `es` | `es` | Español |
| `ja` | `ja` | 日本語 |
| `ca` | `ca` | Català |

`/` 固定进入 `/en/`，官网默认语言为英文；未知语言路径的 404 也使用英文提示。各语言具有首页、`download/`、`protocol/`、`security/`、`changelog/` 与 `docs/`。文档示例：

```text
/zh-hans/docs/getting-started/installation/
/en/docs/getting-started/installation/
/ca/docs/getting-started/installation/
```

语言切换保持稳定文章 ID 和现有片段标识。正文、标题和说明翻译，路径标识统一使用英文。页面 canonical 指向自身的正式语言 URL，`hreflang` 关联实际存在的翻译，`x-default` 指向英文的对应页面。没有翻译时不能静默冒充目标语言页面；现有构建要求全部核心文章七语齐全。未知语言与未知文章须返回真实 HTTP 404。

## 编辑公开文档

先从实际代码、README、usage 与已批准的工程文档核实事实，再编辑 `docs/site/{locale}/`。当前有 18 个稳定文章 ID，每种语言各一篇：

```text
getting-started/{introduction,installation,quick-start}
guides/{server,client,deployment,upgrade}
configuration/{server,client,examples}
concepts/{architecture,transports,security-model}
reference/{cli,configuration,protocol}
troubleshooting
contributing
```

文件通常为 `{id}.mdx`，目录首页也可用 `{id}/index.mdx`。Fumadocs 各级 `meta.json` 控制排序和分组。正文采用标准 Markdown，添加 MDX 交互组件时需要同时考虑 SSR、可访问性和测试。

每篇文件包含以下 frontmatter：

```yaml
---
id: getting-started/installation
title: 安装 Umbra
description: 按系统和架构选择发布版本，验证安装并查看当前版本。
section: getting-started
order: 2
version: 1.0.0-alpha
source:
  - README.zh-CN.md
  - docs/usage.zh-CN.md
translation: complete
---
```

`version` 必须匹配根 `Cargo.toml` 的 `[workspace.package]`。更新版本时逐篇审查实际行为，再同步元数据，不能只修改版本号。`translation: complete` 表示该文件包含完整的目标语言内容，不代表已经通过外部专业翻译认证。

`source` 只允许明确公开的 README、usage/performance/architecture/protocol 文档、贡献说明、许可证、Cargo.toml、发布工作流与 `crates/umbra*/src/**/*.rs`。源文件必须实际存在并位于仓库内。内容工具不读取源文件正文进行自动发布，不扫描 `openspec`、运行记录、私有配置或本地脚本。

新增核心文章时，需要同时更新 `apps/web/tooling/content-lib.ts` 的公开文章清单、全部七语正文、对应 `meta.json`、导航和验证用例。普通文章内部链接推荐使用完整语言路径：

```md
[安装指南](/zh-hans/docs/getting-started/installation/)
[配置章节](/en/docs/getting-started/introduction/#configuration)
```

`pnpm content` 会阻止缺失翻译、重复 ID、无效元数据、无效源路径、过短正文、失效内部链接或不存在的标题引用。标题片段按 GitHub slug 规则生成；修改标题后要检查其他文档是否仍引用旧片段。外部链接不在每次构建中联网探测。

## 内容准确性与发布信息

网站陈述以当前实现为准：保留 alpha 状态，说明当前传输与配置边界，区分历史指纹档案、实际抓包证据和设计目标。不能将协议设计文档中的规划能力写成已经完成的承诺，也不能虚构审计、性能或绝对安全结论。

版本信息从 Cargo 生成，平台信息从 `.github/workflows/dist.yml` 的真实目标矩阵生成。当前下载入口使用 GitHub Releases 列表，构建不请求 GitHub API。只有未来发布流程提供并验证具体资产清单后，才能增加直接文件链接、校验和或签名状态。

生成物如下，均不手动编辑：

| 文件 | 内容 |
| --- | --- |
| `apps/web/public/search/{locale}.json` | 当前语言文章标题、说明、正文和稳定链接 |
| `apps/web/src/content/documents.generated.ts` | 已验证文章的元数据，不含正文 |
| `apps/web/src/content/releases.generated.ts` | Cargo 版本、发行平台和发布列表链接 |

搜索索引按语言拆分，由浏览器按需下载并查询；没有远程查询记录。中文、日文、带重音字符的语言和配置项名称均需要保持可搜索。更新翻译后构建会重新生成对应索引。

## Cloudflare 部署

官网与文档首次访问默认采用浅色主题。用户主动切换深色后，其偏好仅保存在浏览器本地；不跟随系统主题自动切换，也不向后端写入偏好。验证默认主题时应使用没有既有主题偏好的新浏览器上下文。

本地 `pnpm preview` 使用构建产物与 Cloudflare Vite 插件进行预览。普通构建和测试不发布应用，不创建 DNS 或账户资源。

生产发布入口为 `.github/workflows/web-deploy.yml`，只能通过 GitHub Actions 的 **Deploy website → Run workflow** 手动触发。工作流先复用全部网站验证，成功后才发布同一提交。请配置 GitHub 的 `production` environment：

- Secret：`CLOUDFLARE_API_TOKEN`，仅授予目标账户的必要 Workers 发布权限。
- Variable：`CLOUDFLARE_ACCOUNT_ID`，目标 Cloudflare 账户 ID。

不要把真实 token 或账户配置写进仓库。Cloudflare 身份认证也可以用于经验证后的本地发布：

```sh
pnpm --filter @umbra/web deploy
```

这是真实发布命令。Wrangler 配置声明 `umbra.cat` 和 `www.umbra.cat` 两个 Custom Domains，并维护相应的 Cloudflare 托管 DNS 记录；`www` 由应用重定向到主域。域名继续在原注册商注册，外部 Nameservers 修改由维护者手动完成。免费 Full setup 接入时不能仅在外部 DNS 添加指向 workers.dev 的 CNAME。配置 HTTP 缓存时，带哈希资源可长期缓存，SSR HTML 按当前响应头保守处理。任何后续 HTML 边缘缓存都需要明确版本失效策略，且缓存键必须包含语言路径。

预览域名应返回 `noindex`；canonical 仍使用生产域名。发布后验证七种语言的首页、深层文档、下载链接、搜索 JSON、404、sitemap 和 robots，再向用户公布入口。

可复用完整浏览器测试验证远程部署；指定基址后不会启动本地预览服务：

```sh
PLAYWRIGHT_BASE_URL=https://umbra.cat pnpm test:e2e
```

首次接入时，域名 Active 与 HTTPS 证书 Active 是两个独立状态。Full setup 的免费证书由 Cloudflare 自动进行 DNS 验证；等证书签发后再验证 HTTPS，不关闭 TLS 校验。JS 交互按钮在 hydration 前保持禁用，确保真实网络下的首次点击不会丢失；普通链接和文档正文仍可在无 JavaScript 时使用。

## 可选的域名别名

子域名只作为入口重定向，不托管重复正文。DNS/别名规则都属于实际发布时的维护操作：

| 请求 | 永久跳转目标 |
| --- | --- |
| `www.umbra.cat/{path}` | `https://umbra.cat/{path}` |
| `docs.umbra.cat/` | `https://umbra.cat/en/docs/` |
| `en.umbra.cat/` | `https://umbra.cat/en/` |
| `fr.umbra.cat/` | `https://umbra.cat/fr/` |
| `es.umbra.cat/` | `https://umbra.cat/es/` |
| `ja.umbra.cat/` | `https://umbra.cat/ja/` |
| `ca.umbra.cat/` | `https://umbra.cat/ca/` |
| `git.umbra.cat/` | `https://github.com/lotosli/umbra` |

使用 301/308。语言别名的子路径若启用，应映射到同一语言目录并保留路径与片段；文档别名只为已定义的路由设置规则，不能将任意查询参数解释为跳转目标。`git` 只是浏览器入口，clone 地址继续使用 GitHub 正式仓库地址。首次发布可以只启用主域名，其他别名无需提前创建。

## 回滚

在 Cloudflare Worker 的部署/版本页面选择已验证的上一版本并执行回滚，然后重新核对首页与文档深链。也可在已登录的本地环境使用 `pnpm --filter @umbra/web exec wrangler rollback`，交互确认选定版本。若改动过 DNS 或重定向规则，需单独恢复这些规则；Worker 版本回滚不会自动撤销域名设置。

网站没有数据库迁移。源码回退只影响独立的前端应用、公开内容与工作流，不要求回退 Rust 服务或二进制。
