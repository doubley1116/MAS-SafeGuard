# SFT Model Inference Server

FastAPI 推理服务，加载 Qwen2.5-7B-Instruct + LoRA adapter 提供安全审核分类 API。

## 架构

```
frontend_showcase (浏览器 :48317)
       │
       ▼
Node.js server.js (proxy :48317)
       │  POST /v1/chat/completions
       ▼
inference_server (FastAPI :8000)
       │
       ▼
Qwen2.5-7B-Instruct + LoRA adapter (SFT 权重)
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 启动推理服务

```powershell
# 有 GPU（推荐，需 ~16 GB 显存）
python server.py

# 4-bit 量化（显存不够时，需 ~8 GB 显存）
python server.py --quantize int4

# CPU 模式（很慢，仅测试用，需 ~32 GB RAM）
python server.py --device cpu
```

### 3. 验证服务

```bash
curl http://127.0.0.1:8000/health
# {"status":"ready","device":"cuda","base_model":"Qwen/Qwen2.5-7B-Instruct",...}
```

### 4. 启动前端

```powershell
cd ../frontend_showcase
node server.js
```

浏览器打开 `http://127.0.0.1:48317`，进入 **工作流审计** → 右侧栏 **安全核**。

## API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查，返回模型加载状态、设备、显存占用 |
| GET | `/v1/models` | 模型列表 |
| POST | `/v1/chat/completions` | OpenAI 兼容的 chat completion 接口 |

### Chat Completions 请求示例

```json
{
  "model": "qwen2.5-7b-sft-defender",
  "messages": [
    {
      "role": "system",
      "content": "You are SecurityCore..."
    },
    {
      "role": "user",
      "content": "{\"task\":\"查询订单状态\",\"scenario_id\":\"test\",...}"
    }
  ],
  "temperature": 0,
  "max_tokens": 256
}
```

### 响应示例

```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "model": "qwen2.5-7b-sft-defender",
  "choices": [{
    "message": {
      "role": "assistant",
      "content": "{\"allow\":false,\"risk_score\":0.88,\"reason\":\"...\",\"decision\":\"dangerous\",...}"
    }
  }]
}
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--port` | 8000 | 服务端口 |
| `--host` | 127.0.0.1 | 绑定地址 |
| `--device` | auto | 推理设备 (auto/cuda/cpu) |
| `--quantize` | None | 量化方式 (int4/int8) |
| `--base-model` | Qwen/Qwen2.5-7B-Instruct | 基座模型 ID 或本地路径 |
| `--adapter-path` | AuditDataGen/SFT/qwen-sft-output/final_model | LoRA adapter 路径 |
| `--max-new-tokens` | 256 | 最大生成 token 数 |

## 模型信息

| 项目 | 值 |
|---|---|
| 基座模型 | Qwen2.5-7B-Instruct |
| 训练方式 | LoRA (PEFT), r=16, α=32 |
| 可训练参数 | 40.4M (0.53%) |
| 分类类别 | safe / suspicious / dangerous |
| 准确率 | 90.08% |
| Macro F1 | 0.819 |
| 训练样本 | 8,375 条 |

## 数据流

```
前端安全核配置 (api_gateway 模式)
  → Node.js server.js 构造 OpenAI 格式请求
  → POST /v1/chat/completions
  → SFT 模型推理 (<analysis> + <reason> + <decision>)
  → 解析 XML 标签提取 decision
  → 返回 {allow, risk_score, reason, decision}
  → 前端展示审核结果
```
