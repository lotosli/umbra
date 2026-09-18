# 官网依赖与许可证记录

审查日期：2026-09-16。以下版本和许可证来自本次锁定安装后的 `apps/web/node_modules/*/package.json`；完整间接依赖报告来自仓库根目录的 `pnpm licenses list --json`，不是按 npm latest 推断。依赖版本由 `pnpm-workspace.yaml` catalog 和 `pnpm-lock.yaml` 固定。

## 应用直接依赖

| 包 | 已安装版本 | 声明许可证 | 用途 |
| --- | --- | --- | --- |
| `@fontsource-variable/roboto` | 5.3.0 | OFL-1.1 | 自托管 Roboto 可变字体（正文与标题，避免访客请求 Google Fonts CDN） |
| `@fontsource-variable/roboto-mono` | 5.3.0 | OFL-1.1 | 自托管 Roboto Mono 可变字体（等宽与代码文本） |
| `@tanstack/react-router` | 1.170.36 | MIT | 文件路由、页面上下文和导航 |
| `@tanstack/react-start` | 1.168.54 | MIT | SSR 与服务器页面加载 |
| `fumadocs-core` | 16.15.11 | MIT | 文档源、页面树、目录和链接 |
| `fumadocs-ui` | 16.15.11 | MIT | 文档布局与可访问交互组件 |
| `i18next` | 26.4.2 | MIT | 请求独立的翻译实例 |
| `lucide-react` | 1.46.0 | ISC | 界面图标 |
| `next-themes` | 0.4.6 | MIT | 主题状态与系统主题适配 |
| `react` | 19.2.8 | MIT | 页面组件与渲染模型 |
| `react-dom` | 19.2.8 | MIT | 浏览器渲染和 SSR |
| `react-i18next` | 17.0.14 | MIT | React 翻译上下文 |
| `zod` | 4.6.5 | MIT | 文档元数据、服务器输入和工具数据验证 |

## 开发、构建与测试直接依赖

| 包 | 已安装版本 | 声明许可证 | 用途 |
| --- | --- | --- | --- |
| `@cloudflare/vite-plugin` | 1.54.10 | MIT | Workers 构建及本地运行环境 |
| `@eslint/js` | 10.0.1 | MIT | JavaScript lint 基础规则 |
| `@playwright/test` | 1.63.0 | Apache-2.0 | Chromium 浏览器与 SSR 验证 |
| `@tailwindcss/vite` | 4.3.3 | MIT | CSS 构建集成 |
| `@testing-library/dom` | 10.4.2 | MIT | DOM 行为断言 |
| `@testing-library/jest-dom` | 7.0.1 | MIT | 可访问 DOM 状态 matcher |
| `@testing-library/react` | 16.3.3 | MIT | React 组件测试 |
| `@testing-library/user-event` | 14.6.7 | MIT | 键盘、鼠标和表单事件测试 |
| `@types/mdast` | 4.0.4 | MIT | Markdown AST 类型 |
| `@types/node` | 24.13.5 | MIT | Node 构建工具类型 |
| `@types/react` | 19.2.18 | MIT | React 类型 |
| `@types/react-dom` | 19.2.7 | MIT | React DOM 类型 |
| `@vitejs/plugin-react` | 6.1.1 | MIT | React 编译与开发刷新 |
| `@vitest/coverage-v8` | 5.0.1 | MIT | V8 覆盖率采集与闸门 |
| `eslint` | 10.10.0 | MIT | 代码静态检查 |
| `eslint-plugin-react-hooks` | 7.1.1 | MIT | Hooks 规则检查 |
| `fumadocs-mdx` | 15.4.1 | MIT | 构建时编译和按页加载 Markdown/MDX |
| `github-slugger` | 2.0.0 | ISC | 文档标题片段一致性验证 |
| `globals` | 17.12.0 | MIT | lint 环境全局名称清单 |
| `gray-matter` | 4.0.3 | MIT | frontmatter 解析 |
| `jsdom` | 30.0.1 | MIT | 组件测试的 DOM 环境 |
| `remark-gfm` | 4.0.1 | MIT | 表格和 GFM Markdown AST |
| `remark-parse` | 11.0.0 | MIT | Markdown 链接与标题解析 |
| `tailwindcss` | 4.3.3 | MIT | 样式生成 |
| `tsx` | 4.23.13 | MIT | 运行 TypeScript 内容工具 |
| `typescript` | 5.9.3 | Apache-2.0 | strict 类型检查 |
| `typescript-eslint` | 8.70.0 | MIT | TypeScript lint |
| `unified` | 11.0.5 | MIT | 内容校验的 Markdown 处理流程 |
| `vite` | 8.3.0 | MIT | 开发服务器与生产构建 |
| `vitest` | 5.0.1 | MIT | 单元和组件测试运行器 |
| `wrangler` | 4.132.0 | MIT OR Apache-2.0 | Workers 配置、预览与显式部署 |
| `yaml` | 2.9.1 | ISC | 发布矩阵与 CI 定义解析 |

## 间接依赖门禁

执行：

```sh
pnpm --filter @umbra/web run licenses
```

工具 `apps/web/tooling/license-check.ts` 调用现有 `pnpm licenses list --json`，然后由 `licenses-lib.ts` 验证整个已安装依赖树。CI 在构建前执行相同命令，不需要在线扫描服务、账户或 token。报告不会将本地安装路径写入公开网站。

默认允许本次已审查的 SPDX 声明：MIT、ISC、Apache-2.0、MIT OR Apache-2.0、MIT-0、CC0-1.0、BSD-2-Clause、BSD-3-Clause、Unlicense、BlueOak-1.0.0、0BSD、OFL-1.1。OFL-1.1 仅限字体资源（fontsource），遵循其保留作者署名与随包分发许可证文本的要求。未知声明、缺失元数据、空报告和未记录的许可证均使检查失败。组合表达式只接受已列出的精确形式，不自动推断任意组合的兼容性。

以下是按名称、版本和用途限制的例外，不构成对同许可证其他包的整体放行：

| 包 / 平台变体 | 锁定版本 | 声明许可证 | 实际依赖路径与限定用途 |
| --- | --- | --- | --- |
| `argparse` | 2.0.1 | Python-2.0 | TanStack 构建工具 → xmlbuilder2 → js-yaml 的参数解析器 |
| `caniuse-lite` | 1.0.30001810 | CC-BY-4.0 | Babel/Browserslist 编译目标数据，保留上游数据署名与许可证 |
| `lightningcss` 与 `lightningcss-{platform}` | 1.32.0、1.33.0 | MPL-2.0 | Tailwind、Vite 与 TanStack 插件的 CSS 编译器及平台二进制 |
| `@img/sharp-libvips-{platform}` | 1.3.3 | LGPL-3.0-or-later | Cloudflare Vite/Wrangler → Miniflare → Sharp 的本地原生图像运行依赖 |

平台包在 macOS 与 Linux 上名称不同，门禁限定已知平台命名模式和上述精确版本。不同平台安装的包数量可不同，不能用固定总数量代替许可证检查。Sharp/libvips 是本地模拟器依赖；本应用没有使用 Cloudflare Images binding 或导入 Sharp。Lightning CSS 用于生成 CSS。它们的原生二进制不应作为网站静态资源或 Worker 代码复制发布。

这是当前工程使用范围记录。保留依赖包自身的 LICENSE/NOTICE，不删除构建器保留的第三方许可注释。若未来修改上述包源文件、分发其原生二进制或将其直接引入发布运行时，必须重新审查该变更范围，不能沿用仅针对构建工具的记录。

上游资料：[Sharp 安装与平台二进制](https://sharp.pixelplumbing.com/install/)、[Lightning CSS 许可证](https://github.com/parcel-bundler/lightningcss/blob/master/LICENSE)。

## 更新依赖

修改 catalog 后更新锁文件、执行冻结安装验证、许可证门禁、生产构建和全部测试。审阅 `pnpm why <package> --recursive`，核实新增包实际进入的是开发工具、服务器还是浏览器。新增精确例外或更新例外版本时，同步修改本文件、政策测试和 `licenses-lib.ts`；不能只扩大允许范围使 CI 通过。

## 协议图表工具链（2026-09-18）

`@mermaid-js/mermaid-cli@11.17.0`（MIT）仅用于维护者生成静态 SVG；生产浏览器与 Worker 不运行 Mermaid。通过 `tools/render-protocol-diagrams.mjs` 调用已安装的 Chromium，输出不使用 Font Awesome 图标或字体。包的原始 LICENSE/NOTICE 保留在开发依赖中。

新增精确许可证例外：

| 包 | 版本 | pnpm 声明 | 审查及使用范围 |
| --- | --- | --- | --- |
| @fortawesome/fontawesome-free | 7.3.1 | (CC-BY-4.0 AND OFL-1.1 AND MIT) | Mermaid CLI 的图标、字体与代码各自许可；本站不使用这些图标或字体，也不复制这些资源到生产 |
| dompurify | 3.4.15 | (MPL-2.0 OR Apache-2.0) | 采用上游提供的 Apache-2.0 选项；只用于离线 SVG 生成 |
| elkjs | 0.9.3 | EPL-2.0 | Mermaid 布局工具依赖；未修改源代码，不分发其运行库，仅发布生成的图 |
| khroma | 2.1.0 | Unknown | 已核实安装包 `license` 文件为 MIT，作者 Fabio Spampinato / Andrew Maney；元数据遗漏，按包名与版本精确放行 |

上述许可不向其他包或新版本泛化。更新渲染器时必须重新检查锁文件、许可与生产资源。
