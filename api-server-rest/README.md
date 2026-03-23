# CoCo Restful API Server

CoCo guest components 使用轻量级 ttRPC 进行内部通信。`trustiflux-api-server` 通过配置文件决定是否向外暴露机密数据中心（CDH）和认证代理（AA）的 API，并将 HTTP 请求转发到各自的 ttrpc socket。

默认配置文件路径：`/etc/trustiflux/trustiflux-api-server.toml`，示例：

```
bind = "127.0.0.1:8006"
enable_cdh = true
cdh_socket = "unix:///run/confidential-containers/cdh.sock"
allow_remote_resource_injection = false
enable_aa = true
aa_socket = "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
allow_remote_get_evidence = false
```

访问控制说明：

- `allow_remote_get_evidence = true` 时，允许远程访问 `GET /aa/evidence`
- `allow_remote_resource_injection = true` 时，允许远程访问 `POST /cdh/resource-injection/...`
- `GET /cdh/resource/...` 始终只允许本地回环地址访问，不会被上述配置放开
- 其他 `aa` 接口，例如 `GET /aa/token` 和 `POST /aa/aael`，仍然只允许本地访问

启动示例（使用仓库自带配置）：

```bash
$ ./api-server-rest --config dist/rpm/trustiflux-api-server.toml
Starting API server with config dist/rpm/trustiflux-api-server.toml (bind 127.0.0.1:8006)
API Server listening on http://127.0.0.1:8006

$ curl http://127.0.0.1:8006/cdh/resource/default/key/1
12345678901234567890123456xxxx

$ curl "http://127.0.0.1:8006/aa/evidence?runtime_data=xxxx"
{"svn":"1","report_data":"eHh4eA=="}

$ curl "http://127.0.0.1:8006/aa/token?token_type=kbs"
{"token":"eyJhbGciOiJFi...","tee_keypair":"-----BEGIN... "}
```
