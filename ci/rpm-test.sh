#!/usr/bin/env bash
# guest-components RPM 功能测试脚本
#
# 覆盖以下用例:
#   AA-01  安装 RPM 包，检查服务安装成功并启动
#   AA-02  获取 TEE 平台 (attestation-agent-client get-tee)
#   AA-03  获取 Evidence (attestation-agent-client get-evidence)
#   AA-04  获取 Attestation Token (kbs / coco_as 两种 token-type)
#   AA-05  动态扩展度量 (TDX 环境自动启用，extend-runtime-measurement)
#   CDH-01 机密资源获取 (confidential-data-hub get-resource)
#
# 用法:
#   rpm/build-rpm.sh al8                        # 先打 RPM（Alibaba Cloud Linux 3）
#   ./ci/rpm-test.sh                            # 再跑功能测试（自动找 rpm-output/ 下的 RPM）
#   TRUSTEE_URL=http://<地址> ./ci/rpm-test.sh   # 指定完整 trustee 地址（本机或远端）
#
# 前置条件:
#   - 每次测试会自动 yum install/update trustee 并重启服务（SKIP_TRUSTEE_INSTALL=true 跳过）
#   - 测试密钥 kbs:///test/key/model-decryption-key 由脚本自动写入 trustee 资源目录
#     （trustee 配置 /etc/trustee/kbs-config.toml 的 resource 插件:
#     type = "LocalFs", dir_path = "/opt/trustee/kbs/repository"；
#     PROVISION_SECRET=false 可跳过，改为使用 trustee 已有资源）
#
# 可选环境变量:
#   RPM_DIR            RPM 查找目录（默认: <repo>/rpm-output 及 ~/rpmbuild/RPMS）
#   TRUSTEE_URL        trustee 地址，默认 http://127.0.0.1:8081/api
#                      （本机 trustee-gateway，与 dist/rpm/attestation-agent.toml
#                      打包默认值一致；网关将 /api 路由到 kbs:8080）
#   AS_URL             coco_as 地址，默认 <TRUSTEE_URL>/attestation-service
#                      （即 http://127.0.0.1:8081/api/attestation-service，
#                      网关路由到 restful-as:50005）
#   TRUSTEE_PKG        yum 包名，默认 trustee
#   SKIP_TRUSTEE_INSTALL  跳过 trustee 安装/更新，默认 false
#   TRUSTEE_REPO_DIR   trustee 资源存储目录，默认 /opt/trustee/kbs/repository
#   TRUSTEE_SECRET     预置测试密钥的内容，默认 guest-components-ci-test-secret
#   PROVISION_SECRET   是否自动写入测试密钥，默认 true
#   PROVISION_POLICY   是否自动写入放行测试策略（备份原 policy.rego 为 .orig），
#                      默认 false；KBS 策略拒绝(PolicyDeny)时开启可让 CDH-01 通过
#   TRUSTEE_POLICY     KBS 策略文件路径，默认 /opt/trustee/kbs/policy.rego
#   KBS_RESOURCE_URI   CDH 测试的资源 URI，默认 kbs:///test/key/model-decryption-key
#   EXPECTED_SECRET    CDH get-resource 期望返回的资源内容（可选，设置后做精确比对；
#                      未设置且自动预置密钥时默认取 TRUSTEE_SECRET。
#                      注意 cdh-oneshot 的 stdout 是 base64 编码后的资源内容，
#                      脚本会自动解码后再比对）
#   CDH_TIMEOUT        CDH get-resource 超时秒数，默认 120
#   CLEANUP_RPM        测试结束后卸载安装的 RPM 并恢复被脚本修改的环境
#                      （策略/配置备份），默认 true
#   FORCE_TDX_TEST     强制执行动态扩展度量用例（默认自动探测 TDX 环境）
#   SKIP_TDX_TEST      跳过动态扩展度量用例
#
# 说明:
#   - 服务通过 systemd 管理（环境默认提供 systemctl）
#   - 测试日志同时写入 /tmp/guest-components-rpm-test.log

set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

AA_BIN=/usr/bin/attestation-agent
AA_CLIENT=/usr/bin/attestation-agent-client
CDH_BIN=/usr/bin/confidential-data-hub
AA_CONFIG=/etc/trustiflux/attestation-agent.toml
CDH_CONFIG=/etc/trustiflux/confidential-data-hub.toml
AA_SOCK=/run/confidential-containers/attestation-agent/attestation-agent.sock
TEST_LOG=/tmp/guest-components-rpm-test.log

TRUSTEE_URL=${TRUSTEE_URL:-http://127.0.0.1:8081/api}
AS_URL=${AS_URL:-}
TRUSTEE_PKG=${TRUSTEE_PKG:-trustee}
SKIP_TRUSTEE_INSTALL=${SKIP_TRUSTEE_INSTALL:-false}
TRUSTEE_REPO_DIR=${TRUSTEE_REPO_DIR:-/opt/trustee/kbs/repository}
TRUSTEE_SECRET=${TRUSTEE_SECRET:-guest-components-ci-test-secret}
PROVISION_SECRET=${PROVISION_SECRET:-true}
PROVISION_POLICY=${PROVISION_POLICY:-false}
TRUSTEE_POLICY=${TRUSTEE_POLICY:-/opt/trustee/kbs/policy.rego}
KBS_RESOURCE_URI=${KBS_RESOURCE_URI:-kbs:///test/key/model-decryption-key}
EXPECTED_SECRET=${EXPECTED_SECRET:-}
FORCE_TDX_TEST=${FORCE_TDX_TEST:-false}
SKIP_TDX_TEST=${SKIP_TDX_TEST:-false}

PASS=0
FAIL=0
FAILED_CASES=()

log()  { printf "[rpm-test] %s\n" "$*" | tee -a "$TEST_LOG"; }
info() { printf "         %s\n" "$*" | tee -a "$TEST_LOG"; }

pass() {
    PASS=$((PASS + 1))
    printf "[PASS] %s\n" "$*" | tee -a "$TEST_LOG"
}

fail() {
    FAIL=$((FAIL + 1))
    FAILED_CASES+=("$*")
    printf "[FAIL] %s\n" "$*" | tee -a "$TEST_LOG"
}

skip() {
    printf "[SKIP] %s\n" "$*" | tee -a "$TEST_LOG"
}

exec 2> >(tee -a "$TEST_LOG" >&2)

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
# 精确修改 TOML 某个 [section] 下的 key（生成新配置前先备份 *.orig）
# 布尔值 (true/false) 不加引号，其余按字符串写入
set_toml_key() {
    local file=$1 section=$2 key=$3 value=$4
    [ -f "$file" ] || { log "配置文件不存在: $file"; return 1; }
    [ -f "${file}.orig" ] || cp "$file" "${file}.orig"
    awk -v sect="[$section]" -v key="$key" -v val="$value" '
        /^[[:space:]]*\[/ {
            hdr = $0
            gsub(/[[:space:]]/, "", hdr)
            in_section = (hdr == sect)
        }
        in_section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            if (val == "true" || val == "false") {
                sub(/=.*/, "= " val)
            } else {
                sub(/=.*/, "= \"" val "\"")
            }
        }
        { print }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

# attestation-agent 服务管理（环境默认有 systemctl）
aa_start() {
    systemctl start attestation-agent
}

aa_restart() {
    systemctl restart attestation-agent
}

aa_active() {
    systemctl is-active --quiet attestation-agent
}

# 等待 AA 就绪（socket 存在且 get-tee 可用）
wait_aa_ready() {
    local i
    for i in $(seq 1 30); do
        if [ -S "$AA_SOCK" ] && "$AA_CLIENT" --attestation_sock "unix://$AA_SOCK" get-tee >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# 检查 evidence 中是否包含运行度量记录 "0 0 0"
# TDX evidence 为 JSON: {"quote":"<b64>","cc_eventlog":"<b64 事件日志>",...}
# extend-runtime-measurement 写入的事件数据是字面量 "0 0 0" 字符串，
# 经 read_eventlog base64 编码后放在 cc_eventlog 字段里，因此需要:
#   提取 cc_eventlog -> base64 解码 -> 在明文事件日志中查找 "0 0 0"
evidence_has_measurement() {
    local out=$1 evlog
    # 兼容非 TDX / 未来格式: 明文直接包含
    printf '%s' "$out" | grep -q "0 0 0" && return 0
    # TDX: 解出 cc_eventlog 字段的 base64 值
    evlog=$(printf '%s' "$out" \
        | grep -o '"cc_eventlog"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | head -1 \
        | sed -e 's/^[^:]*://' -e 's/^"//' -e 's/"$//')
    [ -n "$evlog" ] || return 1
    printf '%s' "$evlog" | base64 -d 2>/dev/null | grep -q "0 0 0"
}

detect_tdx() {
    [ -e /dev/tdx-attest ] || [ -d /sys/firmware/tdx ] || grep -qi tdx /proc/cpuinfo
}

# 重启 trustee 各组件服务（kbs / rvps / trustee-gateway / *-as）
# 注意: 排除 umbrella 单元 trustee.service——重启它会连带拉停整个 trustee
# 组件且可能起不来；只重启当前处于运行状态的单元
trustee_restart() {
    local units unit
    units=$(systemctl list-unit-files --type=service 2>/dev/null \
        | awk '{print $1}' | grep -E '((trustee|kbs|rvps).*|.*-as)\.service$' \
        | grep -vx 'trustee.service' || true)
    units=$(printf '%s\n' $units | sort -u)
    if [ -n "$units" ]; then
        for unit in $units; do
            systemctl is-active --quiet "$unit" || continue
            if systemctl restart "$unit" >> "$TEST_LOG" 2>&1; then
                info "已重启 $unit"
            else
                log "警告: 重启 $unit 失败"
            fi
        done
    else
        log "未找到 trustee 相关 systemd 服务，若 KBS 缓存了旧策略请手动重启"
    fi
}

# 等待 KBS 资源接口恢复（2xx-4xx 视为就绪；5xx/超时视为未就绪）
kbs_resource_url() {
    printf '%s/kbs/v0/resource/%s' "${TRUSTEE_URL%/}" "${KBS_RESOURCE_URI#kbs:///}"
}

wait_kbs_ready() {
    local i code
    for i in $(seq 1 30); do
        code=$(curl -s -o /dev/null -m 2 -w '%{http_code}' "$(kbs_resource_url)" 2>/dev/null || true)
        case "$code" in
            2*|3*|4*) return 0 ;;
        esac
        sleep 1
    done
    return 1
}

# ---------------------------------------------------------------------------
# 预检查
# ---------------------------------------------------------------------------
: > "$TEST_LOG"
log "开始 guest-components RPM 功能测试 $(date '+%F %T')"
log "REPO_ROOT=$REPO_ROOT"
log "KBS_RESOURCE_URI=$KBS_RESOURCE_URI"
log "systemd 可用，使用 systemctl 管理服务"

# 定位 RPM 产物：依次在候选目录中查找，返回第一个命中的结果
find_rpms() {
    local d found
    for d in "$@"; do
        [ -n "$d" ] && [ -d "$d" ] || continue
        found=$(find "$d" -name '*.rpm' ! -name '*.src.rpm' 2>/dev/null)
        if [ -n "$found" ]; then
            printf '%s\n' "$found"
            return 0
        fi
    done
    return 1
}

RPM_LIST=$(find_rpms "${RPM_DIR:-}" "$REPO_ROOT/rpm-output" "$HOME/rpmbuild/RPMS")
if [ -z "$RPM_LIST" ]; then
    fail "setup 未找到 RPM 产物，请先执行 rpm/build-rpm.sh 或设置 RPM_DIR"
    exit 1
fi
log "待安装 RPM:"
printf '%s\n' "$RPM_LIST" | tee -a "$TEST_LOG"

# coco_as 地址默认取 <TRUSTEE_URL>/attestation-service
# （本机 trustee-gateway 布局: kbs 走 <TRUSTEE_URL>=.../api，AS 走 .../api/attestation-service）
[ -z "$AS_URL" ] && AS_URL="${TRUSTEE_URL%/}/attestation-service"

# ---------------------------------------------------------------------------
# 安装/更新 trustee（每次测试执行，确保用最新版本）
# ---------------------------------------------------------------------------
if [ "$SKIP_TRUSTEE_INSTALL" != "true" ]; then
    log "安装/更新 $TRUSTEE_PKG"
    if yum install -y "$TRUSTEE_PKG" >> "$TEST_LOG" 2>&1 &&
       yum update -y "$TRUSTEE_PKG" >> "$TEST_LOG" 2>&1; then
        info "trustee 安装/更新完成: $(rpm -q "$TRUSTEE_PKG")"
    else
        fail "setup trustee 安装/更新失败（详见 $TEST_LOG）"
    fi

    # 更新后重启相关服务，确保运行新版本
    trustee_restart
else
    log "SKIP_TRUSTEE_INSTALL=true，跳过 trustee 安装/更新"
fi

# ---------------------------------------------------------------------------
# 预置测试密钥 kbs:///test/key/model-decryption-key
# （trustee resource 插件 LocalFs，根目录见 /etc/trustee/kbs-config.toml 的
#   dir_path = /opt/trustee/kbs/repository；嵌套目录与转义文件名两种布局
#   各写一份，兼容不同 trustee 实现）
# ---------------------------------------------------------------------------
if [ "$PROVISION_SECRET" = "true" ]; then
    secret_dir="$TRUSTEE_REPO_DIR/test/key"
    if mkdir -p "$secret_dir" 2>>"$TEST_LOG" &&
       printf '%s' "$TRUSTEE_SECRET" > "$secret_dir/model-decryption-key" 2>>"$TEST_LOG"; then
        info "测试密钥已写入: $secret_dir/model-decryption-key"
    else
        fail "setup 测试密钥写入失败: $secret_dir/model-decryption-key"
    fi

    # 转义文件名布局（上游 CoCo KBS local_fs 风格: / 转为字面量 \x2F）
    escaped="$TRUSTEE_REPO_DIR/test\x2Fkey\x2Fmodel-decryption-key"
    if printf '%s' "$TRUSTEE_SECRET" > "$escaped" 2>>"$TEST_LOG"; then
        info "测试密钥已写入(转义布局): test\\x2Fkey\\x2Fmodel-decryption-key"
    else
        log "警告: 转义布局写入失败（若 trustee 为嵌套布局可忽略）"
    fi

    # 未显式指定期望内容时，用预置的密钥内容做 CDH 精确比对
    [ -z "$EXPECTED_SECRET" ] && EXPECTED_SECRET=$TRUSTEE_SECRET
else
    log "PROVISION_SECRET=false，跳过测试密钥预置"
fi

# 可选: 写入放行策略，避免 KBS 资源访问被 policy.rego 拒绝（PolicyDeny）
# 原 policy.rego 备份为 .orig；CI 专用机器上建议开启
if [ "$PROVISION_POLICY" = "true" ]; then
    if [ -f "$TRUSTEE_POLICY" ]; then
        [ -f "${TRUSTEE_POLICY}.orig" ] || cp "$TRUSTEE_POLICY" "${TRUSTEE_POLICY}.orig"
        if cat > "$TRUSTEE_POLICY" <<'EOF'
package policy

default allow = true
EOF
        then
            info "已写入放行测试策略: $TRUSTEE_POLICY (原策略备份为 .orig)"
            # 重启相关服务使策略生效
            trustee_restart
            if ! wait_kbs_ready; then
                log "警告: KBS 资源接口 30s 内未就绪，后续测试可能失败"
            fi
        else
            fail "setup 写入 $TRUSTEE_POLICY 失败"
        fi
    else
        log "跳过策略预置（缺少 $TRUSTEE_POLICY）"
    fi
fi

# 等待 trustee 就绪（重启后需要几秒，最长等 30s）
for i in $(seq 1 30); do
    http_code=$(curl -s -o /dev/null -m 2 -w '%{http_code}' "$TRUSTEE_URL" 2>/dev/null || true)
    [ "$http_code" != "000" ] && break
    sleep 1
done
log "trustee 预检: $TRUSTEE_URL -> HTTP $http_code"
http_code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$AS_URL" 2>/dev/null || true)
log "trustee 预检: $AS_URL -> HTTP $http_code"
[ "$http_code" = "000" ] && fail "setup trustee 不可达: $AS_URL"

# ---------------------------------------------------------------------------
# AA-01 安装 RPM 包，服务启动
# ---------------------------------------------------------------------------
log ""
log "== 安装 RPM 包 =="

if yum install -y $RPM_LIST >> "$TEST_LOG" 2>&1; then
    pass "rpm-install RPM 安装成功"
else
    fail "rpm-install RPM 安装失败，详见 $TEST_LOG"
    exit 1
fi

for bin in "$AA_BIN" "$AA_CLIENT" "$CDH_BIN"; do
    if [ -x "$bin" ]; then
        info "二进制就位: $bin"
    else
        fail "rpm-install 缺少二进制: $bin"
    fi
done
[ -f "$AA_CONFIG" ] && info "配置文件就位: $AA_CONFIG" || fail "rpm-install 缺少配置: $AA_CONFIG"
[ -f "$CDH_CONFIG" ] && info "配置文件就位: $CDH_CONFIG" || fail "rpm-install 缺少配置: $CDH_CONFIG"

# 安装后确认服务处于运行状态
if ! aa_active; then
    log "安装后服务未运行，尝试 systemctl enable --now attestation-agent"
    systemctl enable --now attestation-agent >> "$TEST_LOG" 2>&1 || true
fi

if aa_active && wait_aa_ready; then
    pass "aa-service attestation-agent 服务运行中"
else
    fail "aa-service attestation-agent 服务未运行"
    info "排查: systemctl status attestation-agent"
fi

# ---------------------------------------------------------------------------
# AA-02 获取 TEE 平台
# ---------------------------------------------------------------------------
log ""
log "== 获取 TEE 平台 =="

if out=$("$AA_CLIENT" --attestation_sock "unix://$AA_SOCK" get-tee 2>&1); then
    if [ -n "$out" ]; then
        pass "get-tee 返回 $out"
    else
        fail "get-tee 返回为空"
    fi
else
    fail "get-tee 执行失败: $out"
fi

# ---------------------------------------------------------------------------
# AA-03 获取 Evidence
# ---------------------------------------------------------------------------
log ""
log "== 获取 Evidence =="

if out=$("$AA_CLIENT" --attestation_sock "unix://$AA_SOCK" get-evidence --runtime-data AAAA 2>&1); then
    if [ "${#out}" -ge 32 ]; then
        pass "get-evidence 成功 (长度 ${#out})"
        info "evidence 前 64 字符: ${out:0:64}..."
    else
        fail "get-evidence 返回过短 (长度 ${#out}): $out"
    fi
else
    fail "get-evidence 执行失败: $out"
fi

# ---------------------------------------------------------------------------
# AA-04 获取 Attestation Token (kbs / coco_as)
# ---------------------------------------------------------------------------
log ""
log "== 获取 Attestation Token =="

# 修改 [token_configs.kbs] 与 [token_configs.coco_as] 的 url 指向 trustee
if set_toml_key "$AA_CONFIG" "token_configs.kbs" "url" "$TRUSTEE_URL" &&
   set_toml_key "$AA_CONFIG" "token_configs.coco_as" "url" "$AS_URL"; then
    info "已配置 trustee 地址 (kbs=$TRUSTEE_URL, coco_as=$AS_URL)"
else
    fail "get-token 修改 $AA_CONFIG 失败"
fi

log "重启 attestation-agent 使配置生效"
aa_restart
if wait_aa_ready; then
    info "服务重启完成"
else
    fail "get-token 服务重启后未就绪"
fi

for ttype in kbs coco_as; do
    if out=$("$AA_CLIENT" --attestation_sock "unix://$AA_SOCK" get-token --token-type "$ttype" 2>&1); then
        # 成功标准: 返回长字符串（JWT 格式为 xxx.yyy.zzz）
        if [ "${#out}" -ge 100 ]; then
            pass "get-token-$ttype 成功 (长度 ${#out})"
            info "token 前 48 字符: ${out:0:48}..."
            if [[ "$out" != *.*.* ]]; then
                info "提示: token 非 JWT 三段式格式，请人工确认内容"
            fi
        else
            fail "get-token-$ttype 返回过短 (长度 ${#out}): $out"
        fi
    else
        fail "get-token-$ttype 执行失败: $out"
    fi
done

# ---------------------------------------------------------------------------
# AA-05 动态扩展度量（仅 TDX 环境）
# ---------------------------------------------------------------------------
log ""
log "== 动态扩展度量 =="

if [ "$SKIP_TDX_TEST" = "true" ]; then
    skip "extend-runtime-measurement SKIP_TDX_TEST=true，跳过"
elif [ "$FORCE_TDX_TEST" = "true" ] || detect_tdx; then
    # 开启 eventlog: enable_eventlog = false -> true（若已是 true 则保持）
    if set_toml_key "$AA_CONFIG" "eventlog_config" "enable_eventlog" "true"; then
        info "已开启 enable_eventlog"
    else
        fail "extend-runtime-measurement 修改 enable_eventlog 失败"
    fi

    log "重启 attestation-agent 使配置生效"
    aa_restart
    wait_aa_ready || fail "extend-runtime-measurement 服务重启后未就绪"

    if out=$("$AA_CLIENT" --attestation_sock "unix://$AA_SOCK" \
             extend-runtime-measurement --domain 0 --operation 0 --content 0 2>&1); then
        if grep -q "Extended" <<<"$out"; then
            pass "extend-runtime-measurement 返回 Extended"
        else
            fail "extend-runtime-measurement 返回异常: $out"
        fi
    else
        fail "extend-runtime-measurement 执行失败: $out"
    fi

    # 检查度量是否写入 evidence（evidence 中出现 "0 0 0"）
    if out=$("$AA_CLIENT" --attestation_sock "unix://$AA_SOCK" get-evidence --runtime-data AAAA 2>&1); then
        if evidence_has_measurement "$out"; then
            pass "runtime-measurement-evidence 包含运行度量记录 (0 0 0)"
        else
            fail "runtime-measurement-evidence 未找到运行度量记录 (0 0 0)"
            info "evidence 前 128 字符: ${out:0:128}..."
            # 打印解码后的事件日志末尾，便于人工排查度量是否写入
            evlog=$(printf '%s' "$out" \
                | grep -o '"cc_eventlog"[[:space:]]*:[[:space:]]*"[^"]*"' \
                | head -1 \
                | sed -e 's/^[^:]*://' -e 's/^"//' -e 's/"$//')
            if [ -n "$evlog" ]; then
                info "事件日志末尾 128 字符: ...$(printf '%s' "$evlog" | base64 -d 2>/dev/null | tail -c 128 | tr -d '\0')"
            else
                info "evidence 中未找到 cc_eventlog 字段"
            fi
        fi
    else
        fail "runtime-measurement-evidence get-evidence 执行失败: $out"
    fi
else
    skip "extend-runtime-measurement 非 TDX 环境（未检测到 /dev/tdx-attest 或 /sys/firmware/tdx），跳过"
fi

# ---------------------------------------------------------------------------
# CDH-01 机密资源获取
# ---------------------------------------------------------------------------
log ""
log "== 机密资源获取 =="

if set_toml_key "$CDH_CONFIG" "kbc" "url" "$TRUSTEE_URL"; then
    info "已配置 CDH kbc url=$TRUSTEE_URL"
else
    fail "get-resource 修改 $CDH_CONFIG 失败"
fi

# 依赖 AA 正常运行（cc_kbc 通过 AA 获取 token）
if ! aa_active || ! wait_aa_ready; then
    log "AA 未就绪，重启服务"
    aa_restart
    wait_aa_ready || fail "get-resource AA 服务未就绪"
fi

# 直接探测 trustee 网关的资源接口（不带 token，预期快速返回 401/404；
# 若超时无响应(HTTP 000)则说明 hang 在 trustee/网关侧，而非 guest-components）
CDH_LOG=/tmp/cdh-oneshot-test.log
res_url=$(kbs_resource_url)
http_code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$res_url" 2>/dev/null || true)
info "网关资源接口探测: $res_url -> HTTP $http_code（无 token 预期 401/404）"
if [ "$http_code" = "000" ]; then
    info "警告: 资源接口 10s 无响应，CDH get-resource 的 hang 可能出在 trustee/网关侧"
fi

# get-resource 失败时会循环重试，务必用 timeout 兜底。
# stdout 为 base64 编码的资源内容（cdh-oneshot 对输出做了 STANDARD.encode），
# 日志走 stderr，单独落盘避免污染比对；RUST_LOG=debug 输出各阶段进度便于定位
: > "$CDH_LOG"
if out=$(RUST_LOG=debug timeout "${CDH_TIMEOUT:-120}" "$CDH_BIN" -c "$CDH_CONFIG" --retry 1 \
         get-resource --resource-uri "$KBS_RESOURCE_URI" 2>"$CDH_LOG"); then
    # 取 stdout 最后一行作为 base64 资源内容解码
    decoded=$(printf '%s' "$out" | tail -n 1 | base64 -d 2>/dev/null)
    if [ -n "$decoded" ]; then
        if [ -n "$EXPECTED_SECRET" ]; then
            if [ "$decoded" = "$EXPECTED_SECRET" ]; then
                pass "get-resource 成功，内容与 EXPECTED_SECRET 一致"
            else
                fail "get-resource 内容与期望不符"
                info "期望: $EXPECTED_SECRET"
                info "实际: $decoded"
            fi
        else
            pass "get-resource 成功 (长度 ${#decoded})"
            info "资源内容前 64 字符: ${decoded:0:64}"
        fi
    else
        fail "get-resource 返回为空或 base64 解码失败"
        info "stdout: ${out:0:200}"
    fi
else
    fail "get-resource 执行失败（超时 ${CDH_TIMEOUT:-120}s 或报错）"
    # 定位根因: PolicyDeny 是 trustee 侧 KBS 策略拒绝，非 guest-components 问题
    if grep -q "PolicyDeny" "$CDH_LOG" 2>/dev/null; then
        info "根因: trustee KBS 策略拒绝 (PolicyDeny / Access denied by policy)"
        info "处理: 检查 $TRUSTEE_POLICY 中的策略规则，或设置 PROVISION_POLICY=true"
        info "      由脚本写入放行测试策略（原策略自动备份为 .orig）"
    fi
    info "CDH 日志已落盘: $CDH_LOG，末尾内容:"
    tail -n 20 "$CDH_LOG" | while IFS= read -r line; do info "  $line"; done
fi

# ---------------------------------------------------------------------------
# 清理: 卸载测试安装的 RPM 包，恢复被脚本修改过的环境
# ---------------------------------------------------------------------------
if [ "${CLEANUP_RPM:-true}" = "true" ]; then
    log ""
    log "清理: 卸载测试安装的 RPM"
    # 从 RPM 文件解析包名（不依赖文件路径在卸载时仍存在）
    pkg_names=$(printf '%s\n' "$RPM_LIST" | while IFS= read -r f; do
        rpm -qp --queryformat '%{NAME}\n' "$f" 2>/dev/null
    done)
    installed=""
    for p in $pkg_names; do
        rpm -q "$p" >/dev/null 2>&1 && installed="$installed $p"
    done
    if [ -n "$installed" ]; then
        if yum remove -y $installed >> "$TEST_LOG" 2>&1; then
            info "已卸载 RPM:$installed"
        else
            fail "cleanup RPM 卸载失败:$installed（详见 $TEST_LOG）"
        fi
    else
        log "RPM 均已不在安装列表，无需卸载"
    fi

    # 清理脚本生成的配置备份
    rm -f "$AA_CONFIG.orig" "$CDH_CONFIG.orig"

    # 恢复预置策略前的原始 policy.rego
    if [ -f "${TRUSTEE_POLICY}.orig" ]; then
        if mv -f "${TRUSTEE_POLICY}.orig" "$TRUSTEE_POLICY" 2>>"$TEST_LOG"; then
            log "已恢复原始 KBS 策略: $TRUSTEE_POLICY"
            trustee_restart
        else
            log "警告: 恢复 $TRUSTEE_POLICY 失败"
        fi
    fi
else
    log "CLEANUP_RPM=false，保留已安装的 RPM 与策略修改"
fi

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
log ""
log "================ 测试汇总 ================"
log "PASS: $PASS    FAIL: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    log "失败用例:"
    for c in "${FAILED_CASES[@]}"; do
        log "  - $c"
    done
fi
log "完整日志: $TEST_LOG"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
