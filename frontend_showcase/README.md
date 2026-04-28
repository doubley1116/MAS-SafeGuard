# Frontend Showcase

这是一个用于本地项目展示的前端演示页，直接放在当前仓库里，方便做答辩、汇报和功能演示。

## 启动方式

推荐直接运行：

```powershell
powershell -ExecutionPolicy Bypass -File "C:\gpbell\grade2_2\Zero_Trust\frontend_showcase\start_showcase.ps1"
```

脚本会：
1. 启动本地 PowerShell 服务
2. 尝试自动打开浏览器
3. 访问 `http://127.0.0.1:48317`

如果你只想看静态页面，也可以直接打开：

- `frontend_showcase/index.html`

## 当前支持的展示能力

- Workflow 列表、详情、状态标签
- Block reason、risk tags、suggested alternative
- History 弹窗查看
- Security Core 总开关
- 本地模型 / API 模型 双入口
- 前端配置编辑并实时生成 YAML
- 审计日志流展示
- 自动扫描仓库中的 `policy.yaml`
- 自动读取真实 `audit_logs/workflows/*.json`
- 自动监听新生成的 `workflow.json` 并实时刷新前端

## 模型入口能力

`Security Core` 面板现在支持两种模式：

- `local_model`
  - 本地模型路径
  - provider
  - model_name

- `api_gateway`
  - API 协议类型
  - API Base URL
  - API Route
  - API Key Env
  - Timeout
  - provider
  - model_name

当前还额外预留了：

- `prompt_status: pending`

也就是说模型提示词入口已经留好了位置，后续你可以继续把 prompt 接到 API 请求层或本地模型推理层。

## 设计方向

这版界面不再只是普通后台面板，而是调整成：

- Apple 风格的克制大标题、简洁按钮、玻璃感卡片
- NASA 风格的深色太空背景、mission console 氛围、轨道视觉和任务叙事
- 支持 `Apple x NASA / Apple Glass / Mission Control` 三种主题标签切换

参考页面：

- [Apple](https://www.apple.com/)
- [NASA](https://www.nasa.gov/)

这两站当前首页给我们的设计启发主要是：

- Apple：大标题、少量高强度 CTA、留白和聚焦式产品陈列
- NASA：深色沉浸背景、任务式信息分层、专题模块和 mission 状态感

## 自动监听说明

真实文件模式下，页面提供：

- `Auto Refresh` 开关
- `3s / 5s / 10s` 轮询间隔
- 当前监听状态
- 最近检查时间
- 最近变更时间

后端接口包括：

- `/api/discover`
- `/api/filesystem`
- `/api/workflow-watch`

其中 `/api/workflow-watch` 返回：

- `workflowDir`
- `workflowCount`
- `latestModified`
- `fingerprint`
- `scannedAt`

前端通过目录指纹变化判断是否有新的 `workflow.json`，检测到变化后会自动重新载入 workflow 列表、详情和日志视图。

## 主要文件

- `frontend_showcase/index.html`：页面结构
- `frontend_showcase/styles.css`：视觉样式
- `frontend_showcase/app.js`：前端交互、真实文件读取、自动刷新、YAML 生成
- `frontend_showcase/showcase_server.ps1`：PowerShell 本地静态服务与文件系统 API
- `frontend_showcase/start_showcase.ps1`：一键启动脚本
- `frontend_showcase/server.js`：Node 版备用服务实现

## 兼容性与验证

- 已兼容 Windows PowerShell 5
- 已修复真实 workflow 解析问题
- 已通过 `app.js` 语法检查
- 已通过 `showcase_server.ps1` 语法检查
- 已验证 `/api/workflow-watch` 正常返回
- 已通过浏览器自动化验证：
  - 新版 Hero 渲染成功
  - API 模型字段会在 `api_gateway` 模式下出现
  - 主题切换会更新页面主题状态
