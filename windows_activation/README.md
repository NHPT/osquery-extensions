# windows_activation

`windows_activation` 是一个仅适用于 Windows 的 osquery extension table，用于查询当前系统的 Windows 许可证/激活状态信息。

当前实现基于 Go 原生调用 WMI 查询，不依赖 PowerShell，不解析 `slmgr.vbs` 文本输出，主要返回后端当前需要的最小字段集。

## 功能说明

- 表名：`windows_activation`
- 适用平台：Windows
- 查询方式：
  - `SoftwareLicensingProduct`
  - `SoftwareLicensingService`
- 主要用途：
  - 判断系统是否已激活
  - 判断当前许可状态
  - 识别激活通道，如 `kms_client`、`mak`、`retail`、`oem`
  - 获取 KMS 配置的服务器和端口

## 返回字段

| 字段名 | 说明 |
| --- | --- |
| `product_description` | Windows 许可产品描述，通常可看出版本/通道信息 |
| `license_status_code` | 许可证状态码 |
| `license_status` | 许可证状态文本，如 `Licensed`、`Unlicensed` |
| `is_activated` | 是否已激活，`true` 或 `false` |
| `activation_channel` | 激活通道，当前可能返回 `kms_client`、`mak`、`retail`、`oem`、`adba`、`kms`、`unknown` |
| `grace_period_remaining_minutes` | 剩余宽限分钟数 |
| `kms_configured_machine` | 当前配置的 KMS 主机名 |
| `kms_configured_port` | 当前配置的 KMS 端口 |
| `query_error` | 查询异常信息，成功时通常为空字符串 |

## 状态码说明

当前 `license_status_code` 与 `license_status` 的映射关系如下：

| 状态码 | 状态文本 |
| --- | --- |
| `0` | `Unlicensed` |
| `1` | `Licensed` |
| `2` | `OOBGrace` |
| `3` | `OOTGrace` |
| `4` | `NonGenuineGrace` |
| `5` | `Notification` |
| `6` | `ExtendedGrace` |

## 查询 SQL

```sql
select * from windows_activation;
```

也可以只取关心的字段：

```sql
select
  product_description,
  license_status_code,
  license_status,
  is_activated,
  activation_channel,
  grace_period_remaining_minutes,
  kms_configured_machine,
  kms_configured_port,
  query_error
from windows_activation;
```

## 查询结果示例

```sql
osquery> select * from windows_activation;
+-------------------------------------------------------+---------------------+----------------+--------------+--------------------+--------------------------------+------------------------+---------------------+-------------+
| product_description                                   | license_status_code | license_status | is_activated | activation_channel | grace_period_remaining_minutes | kms_configured_machine | kms_configured_port | query_error |
+-------------------------------------------------------+---------------------+----------------+--------------+--------------------+--------------------------------+------------------------+---------------------+-------------+
| Windows(R) Operating System, VOLUME_KMSCLIENT channel | 1                   | Licensed       | true         | kms_client         | 252189                         | cloudkms.ivolces.com   | 1688                |             |
+-------------------------------------------------------+---------------------+----------------+--------------+--------------------+--------------------------------+------------------------+---------------------+-------------+
```

对应含义：

- 当前系统已激活
- 当前许可证状态为 `Licensed`
- 激活通道为 `kms_client`
- 当前配置的 KMS 服务器为 `cloudkms.ivolces.com:1688`

## 编译

在扩展目录下执行：

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o windows_activation.ext.exe .
```

## 加载方式

示例 `extensions.load` 内容：

```text
C:\Program Files\osquery\extensions\windows_activation.ext.exe
```

`osquery.flags` 中需要包含：

```text
--extensions_autoload=C:\Program Files\osquery\extensions.load
```

## 说明

- 该扩展只支持 Windows。
- 当前实现使用 WMI，字段来源是系统许可服务本身。
- 如果部分环境下 WMI 返回缺失字段，扩展会尽量补查 `SoftwareLicensingService`。
- 如果查询失败，`query_error` 会返回错误信息，便于排查现场环境问题。
