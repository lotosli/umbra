# Proposal

## Why

现有官网标题偏细、说明和控件字号偏小，页面缺少用户期望的开阔感与视觉力度。用户指定 https://gpui-kit.com/ 为整站重做的布局、风格和颜色参考。

## What Changes

- 以 GPUI Kit 的黑白灰设计语言重做官网：宽幅容器、粗体标题、清晰的正文层级、浅网格首屏、黑色主按钮、细边框和克制的阴影。
- 重排首页为左侧主张与入口、右侧大尺寸代码窗口，再接能力网格、入门与文档入口、收尾与页脚。
- 下载、协议、安全、更新列表和更新详情同步重做；文档布局、搜索、导航和主题控件使用同一套视觉变量。
- 覆盖全部七种语言、浅色与深色主题、桌面与移动端；保留 Umbra 的品牌、真实产品内容和既有功能。
- 在本地完成构建、类型与 lint、覆盖率和浏览器验收。无 BREAKING 路由/API 变更。

## Capabilities

### New Capabilities

- `website-visual-system`: 参考 GPUI Kit 的整站视觉规范、首页展示构成与跨语言响应式验收。现有网站功能合同记录于尚未归档的 `add-multilingual-website`，本变更只补充视觉要求。

### Modified Capabilities

None. `openspec/specs/` 当前只有 Rust 能力；原网站功能合同继续适用。

## Impact

主要涉及 `apps/web/src/styles/`、`apps/web/src/components/`、必要的七语营销文案与测试，以及官网开发说明。复用当前 React/TanStack/Fumadocs 技术栈与图标。无需新增 UI 框架、后端、Rust 改动或部署配置。

## Approval

状态：已批准。用户于 2026-09-18 明确回复：“请确认按这份方案实施并提交cloudflare”。此授权覆盖本规格实施、验证、必要的代码提交及通过既有 Cloudflare 发布路径部署和线上验收。
