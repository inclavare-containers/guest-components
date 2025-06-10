# AA Instance 配置说明

## 概述

`aa_instance` 配置项允许 Attestation Agent 获取运行实例的信息，并将其设置到环境变量 `AA_INSTANCE_INFO` 中。

## 配置选项

在配置文件中添加 `[aa_instance]` 段落：

```toml
[aa_instance]

# 是否启用心跳功能（可选，默认为 false）
heartbeat_enabled = false

# AA实例类型（目前仅支持 "aliyun_ecs"）
instance_type = "aliyun_ecs"
```

### 配置参数说明

- `heartbeat_enabled` (可选): 布尔值，指定是否启用心跳功能。默认为 `false`。
- `instance_type` (可选): 字符串，指定AA实例的类型。当前支持的值：
  - `"aliyun_ecs"`: 阿里云ECS实例

## 功能说明

1. **初始化时获取实例信息**: 当 AttestationAgent 对象初始化时，如果配置了 `instance_type`，系统会：
   - 调用相应的实例信息获取模块
   - 获取当前运行环境的实例信息
   - 将获取到的信息写入环境变量 `AA_INSTANCE_INFO`

2. **错误处理**: 如果获取实例信息失败（例如不在相应的云环境中），系统会：
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
heartbeat_enabled = true
instance_type = "aliyun_ecs"
```

## 环境变量

- `AA_INSTANCE_INFO`: 包含实例信息的JSON字符串
- `TRUSTEE_URL`: trustee gateway URL
