# AA Instance 配置说明

## 概述

`aa_instance` 配置项允许 Attestation Agent 获取运行实例的信息，并将其设置到环境变量 `AA_INSTANCE_INFO` 中。

## 配置选项

在配置文件中添加 `[aa_instance]` 段落：

```toml
[aa_instance]

# AA实例类型（目前支持 "aliyun_ecs" / "aliyun_eas"）
instance_type = "aliyun_ecs"

[aa_instance.heartbeat]

# 是否启用心跳功能（可选，默认为 false）
enabled = true

# Trustee服务器URL（可选，如果不设置将从环境变量TRUSTEE_URL获取）
trustee_url = "https://trustee-server.example.com"

# 心跳间隔，以分钟为单位（可选，默认为 5）
interval_minutes = 3
```

### 配置参数说明

- `instance_type` (可选): 字符串，指定AA实例的类型。当前支持的值：
  - `"aliyun_ecs"`: 阿里云ECS实例
  - `"aliyun_eas"`: 阿里云EAS实例

#### heartbeat 子配置
- `enabled` (可选): 布尔值，指定是否启用心跳功能。默认为 `false`。
- `trustee_url` (可选): 字符串，Trustee服务器的URL。如果不设置，将从环境变量 `TRUSTEE_URL` 获取。
- `interval_minutes` (可选): 数字，心跳发送间隔，以分钟为单位。默认为 `5` 分钟。

## 功能说明

1. **初始化时获取实例信息**: 当 AttestationAgent 对象初始化时，如果配置了 `instance_type`，系统会：
   - 调用相应的实例信息获取模块
   - 获取当前运行环境的实例信息
   - 将获取到的信息写入环境变量 `AA_INSTANCE_INFO`

2. **心跳功能**: 如果启用了 `aa_instance.heartbeat.enabled`，系统会：
   - 按配置的间隔（默认5分钟）向TRUSTEE服务器发送心跳请求
   - URL获取优先级：环境变量 `TRUSTEE_URL` > 配置文件 `trustee_url`
   - API路径: `/aa-instance/heartbeat`, 此API由Trustee Gateway提供
   - 在请求头中携带 `AAInstanceInfo`，值为 `AA_INSTANCE_INFO` 环境变量的内容
   - 如果心跳失败，记录警告日志但不影响服务运行

3. **错误处理**: 如果获取实例信息失败（例如不在相应的云环境中），系统会：
   - 记录警告日志
   - 继续正常初始化，不影响其他功能

## 支持的实例类型

### aliyun_ecs

获取阿里云ECS实例的元数据信息，包括：
- 实例ID (instance_id)
- 实例名称 (instance_name)  
- 账户ID (owner_account_id)
- 镜像ID (image_id)

返回的信息以JSON格式存储在环境变量中。

### aliyun_eas

从环境变量读取EAS实例信息，包括：
- 模型ID (eas_model_id) - 环境变量 `EAS_MODEL_ID`
- 实例ID (eas_instance_id) - 环境变量 `EAS_INSTANCE_ID`

如果环境变量未设置，则对应字段为空字符串。返回的信息以JSON格式存储在环境变量中。

## 使用示例

```toml
# 完整配置示例
[token_configs]
# ... 其他token配置 ...

[eventlog_config]
eventlog_algorithm = "sha384"
init_pcr = 17
enable_eventlog = false

[aa_instance]
instance_type = "aliyun_ecs"

[aa_instance.heartbeat]
enabled = true
trustee_url = "https://trustee-server.example.com"
interval_minutes = 3
```

## 环境变量

- `AA_INSTANCE_INFO`: 包含实例信息的JSON字符串
- `TRUSTEE_URL`: trustee gateway URL
- `EAS_MODEL_ID`: EAS模型ID（aliyun_eas）
- `EAS_INSTANCE_ID`: EAS实例ID（aliyun_eas）
