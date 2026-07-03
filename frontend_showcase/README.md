# Frontend Showcase

这是一个用于本地项目展示的前端演示页，直接放在当前仓库里，方便做答辩、汇报和功能演示。

## 启动方式

推荐直接运行：

```powershell
powershell -ExecutionPolicy Bypass -File "C:\gpbell\grade2_2\Zero_Trust\frontend_showcase\start_showcase.ps1"
```

脚本会：
1. 优先启动 Node 本地服务，找不到 Node 时回退到 PowerShell 服务
2. 尝试自动打开浏览器
3. 访问 `http://127.0.0.1:48317`

页面内的 `Demo Console` 需要 Node 服务提供 `/api/demo/*` 接口；推荐使用启动脚本，不要只打开静态 HTML。

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
- 页面内 Demo Console，可选择框架、领域场景、攻击类型并运行演示
- Replay 稳定演示 / Live 真实 MAS 运行双模式
- 运行实例看板、依赖/API 预检、Agent 证据链、拦截原因矩阵
- 演示运行后自动生成真实 `audit_logs/workflows/*.json`
- 自动扫描仓库中的 `policy.yaml`
- 自动读取真实 `audit_logs/workflows/*.json`
- 自动监听新生成的 `workflow.json` 并实时刷新前端
- 人工审核表单、批准继续与拒绝终止双分支
- 后端写入 `audit_logs/reviews/*.json`，并追加恢复、沙箱结果或终止事件

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

这版界面定位为本地演示控制台，重点突出运行路径、审计证据和人工审核闭环：

- 浅色卡片、清晰层级和更易读的表单控件
- 单页面多级导航索引，一级只保留总览、动态演示、工作流审计、设置与日志
- 数据接入、策略配置、日志、仓库映射收进二级导航，避免一级入口过多
- 场景库、运行前检查、终端 stdout/stderr、事件时间线默认折叠，点击后查看细节
- Demo Console 以“选择 -> 预检 -> 运行 -> 证据链 -> 审计 JSON”的叙事组织
- 人工审核默认只显示流程结论，展开后查看审核意见、恢复事件和审计文件

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
- `/api/demo/scenarios`
- `/api/demo/run`
- `/api/demo/jobs/:jobId`
- `/api/human-review`

其中 `/api/workflow-watch` 返回：

- `workflowDir`
- `workflowCount`
- `latestModified`
- `fingerprint`
- `scannedAt`

前端通过目录指纹变化判断是否有新的 `workflow.json`，检测到变化后会自动重新载入 workflow 列表、详情和日志视图。

## 动态演示控制台

`Demo Console` 会从 `MAS/` 自动扫描 3 个框架和 3 个业务领域：

- 框架：`AutoGen`、`CrewAI`、`LangGraph`
- 领域：电商、医疗、金融交易
- 攻击类型：路径绕过、调用者伪装、语义注入、路由劫持、间接提示注入、Agent-in-the-Middle、感染式传播、正常防御链路

演示模式：

- `Replay 稳定演示`：推荐组会和客户展示使用，不依赖外部模型 API 是否可用，会稳定生成 workflow JSON 和证据链。
- `Live 真实运行 MAS`：真实执行对应 MAS 脚本，需要 Python 依赖和 `API_KEY / BASE_URL / MODEL` 等环境变量完整可用。

点击 `运行演示` 后，页面会显示：

- 预检卡片：脚本入口、运行模式、Security Core 入口、攻击画像
- 运行实例看板：任务状态、环境诊断、SecurityCore 决策、审计证据
- Agent 证据链：User / Router / Agent / Tool / SecurityCore / AuditLogger
- 决策矩阵：RuleEngine、LLMReviewer、History Window、Workflow JSON 为什么拦截
- 终端输出：保留 stdout/stderr，方便排查依赖或 API 环境问题

本地服务会写入一个真实 workflow JSON 到 `frontend_showcase/audit_logs/workflows/`，前端随后切到真实文件模式并刷新证据视图。

## 推荐组会演示步骤

1. 运行 `start_showcase.ps1`，打开 `http://127.0.0.1:48317`。
2. 点击顶部导航 `动态演示`。
3. 选择一个框架，例如 `CrewAI`。
4. 选择一个领域，例如 `医疗`。
5. 选择一个攻击类型，例如 `间接提示注入`。
6. 演示模式先选 `Replay 稳定演示`。
7. 点击 `运行演示`，讲解预检、Agent 证据链、拦截原因矩阵和终端输出。
8. 点击 `载入生成结果` 或切到 `工作流审计`，展示生成的 workflow JSON 时间线和 history 窗口。
9. 选择“交易执行待人工复核”，填写审核人和意见，演示“批准并继续（安全沙箱）”或“拒绝并终止”。
10. 展开审核后历史，展示人工决定、工作流恢复、沙箱结果和审计落盘事件。
11. 如果现场环境变量和依赖都配置好了，再切 `Live 真实运行 MAS` 做真实脚本演示。

## 主要文件

- `frontend_showcase/index.html`：页面结构
- `frontend_showcase/styles.css`：视觉样式
- `frontend_showcase/app.js`：前端交互、真实文件读取、自动刷新、YAML 生成
- `frontend_showcase/server.js`：Node 本地服务、文件系统 API、Demo Console 运行器
- `frontend_showcase/showcase_server.ps1`：PowerShell 回退服务
- `frontend_showcase/start_showcase.ps1`：一键启动脚本

## 兼容性与验证

- 已兼容 Windows PowerShell 5
- 已修复真实 workflow 解析问题
- 已通过 `app.js` 语法检查
- 已通过 `server.js` 语法检查
- 已通过 `showcase_server.ps1` 语法检查
- 已验证 `/api/workflow-watch` 正常返回
- 已验证 `/api/demo/scenarios`、`/api/demo/run`、`/api/demo/jobs/:jobId` 可运行并生成 workflow
- 已验证可扫描 9 个 MAS 场景，并返回每个场景支持的攻击类型
- 已验证 `Replay` 模式可生成带 `attack_id / attack_label / audit_layer` 元数据的 workflow JSON
- 已验证 `/api/human-review` 的批准与拒绝分支均会生成真实审核 JSON
- 已验证批准分支追加恢复、沙箱工具结果和完成事件，拒绝分支保持敏感工具未执行
- 已通过浏览器自动化验证：
  - 新版 Hero 渲染成功
  - API 模型字段会在 API 入口模式下出现
  - 主题切换会更新页面主题状态
