#!/usr/bin/env python3
"""
阿里云飞天专有云 v3.16.2 — 云监控采集脚本
产品支持：OSS 对象存储 / MQ 消息队列（RocketMQ）

调用原理：
  云监控 API 是标准 HTTP 接口，Action 作为普通查询参数传递。
  认证方式为 HMAC-SHA1 签名（SignatureVersion=1.0），SDK 内部也是同样逻辑。
  公式：Signature = Base64( HMAC-SHA1(SK+"&", "GET&%2F&"+encode(排序后参数串)) )

仅依赖 Python 3 标准库，无需安装任何第三方包，支持内网离线部署。
"""

# ── 标准库导入（全部内置，无需安装）────────────────────────────────────────────
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import ssl
import time
import urllib.parse
import urllib.request
import uuid

# ══════════════════════════════════════════════════════════════════════════════
# § 1  配置区 —— 部署前按实际环境修改这里
# ══════════════════════════════════════════════════════════════════════════════
API_ENDPOINT   = "https://cms.cn-hangzhou.example.com"  # 云监控 CMS 接口地址
ACCESS_KEY_ID  = "YOUR_ACCESS_KEY_ID"                   # 阿里云 AccessKey ID
ACCESS_KEY_SECRET = "YOUR_ACCESS_KEY_SECRET"            # 阿里云 AccessKey Secret
REGION_ID      = "cn-hangzhou"                          # 环境 Region，如 cn-hangzhou-xxx

# 专有云额外 Header，公共云留空即可；
# 专有云需要填写以指定操作的组织/资源集范围，否则默认指向 root 组织
ORG_ID            = ""   # x-acs-organizationid    组织 ID
RESOURCE_GROUP_ID = ""   # x-acs-resourcegroupid  资源集 ID
INSTANCE_ID       = ""   # x-acs-instanceid       实例 ID（列表查询场景不填）

# ══════════════════════════════════════════════════════════════════════════════
# § 2  监控项定义 —— 来自开发手册"云产品监控项"章节
#       格式：{ MetricName: (中文说明, 单位) }
# ══════════════════════════════════════════════════════════════════════════════

# OSS Namespace: acs_oss_dashboard  维度: userId, BucketName  周期: 60s
# ── 服务总览 ──────────────────────────────────────────────────────────────────
OSS_METRICS_OVERVIEW = {
    "Availability":                      ("可用性",              "%"),
    "RequestValidRate":                  ("有效请求率",           "%"),
    "TotalRequestCount":                 ("总请求数",             "Count"),
    "ValidRequestCount":                 ("有效请求数",           "Count"),
    "InternetSend":                      ("公网流出流量",          "Bytes"),
    "InternetRecv":                      ("公网流入流量",          "Bytes"),
    "IntranetSend":                      ("内网流出流量",          "Bytes"),
    "IntranetRecv":                      ("内网流入流量",          "Bytes"),
    "CdnSend":                           ("CDN流出流量",           "Bytes"),
    "CdnRecv":                           ("CDN流入流量",           "Bytes"),
    "SyncSend":                          ("跨区域复制流出流量",    "Bytes"),
    "SyncRecv":                          ("跨区域复制流入流量",    "Bytes"),
    "MeteringStorageUtilization":        ("存储大小",              "Bytes"),
    "MeteringStorageUtilizationGB":      ("存储大小GB",            "Gbytes"),
    "MeteringStorageUtilizationPercent": ("存储使用率",            "%"),
}
# ── 请求状态详情 ───────────────────────────────────────────────────────────────
OSS_METRICS_REQUEST = {
    "ServerErrorCount":            ("服务端错误请求数",         "Count"),
    "ServerErrorRate":             ("服务端错误请求占比",        "%"),
    "NetworkErrorCount":           ("网络错误请求数",            "Count"),
    "NetworkErrorRate":            ("网络错误请求占比",          "%"),
    "AuthorizationErrorCount":     ("客户端授权错误请求数",      "Count"),
    "AuthorizationErrorRate":      ("客户端授权错误请求占比",    "%"),
    "ResourceNotFoundErrorCount":  ("客户端资源不存在错误请求数","Count"),
    "ResourceNotFoundErrorRate":   ("客户端资源不存在错误占比",  "%"),
    "ClientTimeoutErrorCount":     ("客户端超时错误请求数",      "Count"),
    "ClientTimeoutErrorRate":      ("客户端超时错误请求占比",    "%"),
    "ClientOtherErrorCount":       ("客户端其他错误请求数",      "Count"),
    "ClientOtherErrorRate":        ("客户端其他错误请求占比",    "%"),
    "SuccessCount":                ("成功请求总数",              "Count"),
    "SuccessRate":                 ("成功请求占比",              "%"),
    "RedirectCount":               ("重定向请求总数",            "Count"),
    "RedirectRate":                ("重定向请求占比",            "%"),
}
# ── 最大延时 ──────────────────────────────────────────────────────────────────
OSS_METRICS_LATENCY = {
    "MaxGetObjectE2eLatency":          ("GetObject最大E2E延时",          "ms"),
    "MaxGetObjectServerLatency":       ("GetObject最大服务器延时",        "ms"),
    "MaxHeadObjectE2eLatency":         ("HeadObject最大E2E延时",          "ms"),
    "MaxHeadObjectServerLatency":      ("HeadObject最大服务器延时",       "ms"),
    "MaxPostObjectE2eLatency":         ("PostObject最大E2E延时",          "ms"),
    "MaxPostObjectServerLatency":      ("PostObject最大服务器延时",       "ms"),
    "MaxPutObjectE2eLatency":          ("PutObject最大E2E延时",           "ms"),
    "MaxPutObjectServerLatency":       ("PutObject最大服务器延时",        "ms"),
    "MaxAppendObjectE2eLatency":       ("AppendObject最大E2E延时",        "ms"),
    "MaxAppendObjectServerLatency":    ("AppendObject最大服务器延时",     "ms"),
    "MaxUploadPartE2eLatency":         ("UploadPart最大E2E延时",          "ms"),
    "MaxUploadPartServerLatency":      ("UploadPart最大服务器延时",       "ms"),
    "MaxUploadPartCopyE2eLatency":     ("UploadPartCopy最大E2E延时",      "ms"),
    "MaxUploadPartCopyServerLatency":  ("UploadPartCopy最大服务器延时",   "ms"),
}
# ── 成功请求操作分类 ──────────────────────────────────────────────────────────
OSS_METRICS_OPS = {
    "GetObjectCount":       ("GetObject成功请求数",       "Count"),
    "HeadObjectCount":      ("HeadObject成功请求数",      "Count"),
    "PutObjectCount":       ("PutObject成功请求数",       "Count"),
    "PostObjectCount":      ("PostObject成功请求数",      "Count"),
    "AppendObjectCount":    ("AppendObject成功请求数",    "Count"),
    "UploadPartCount":      ("UploadPart成功请求数",      "Count"),
    "UploadPartCopyCount":  ("UploadPartCopy成功请求数",  "Count"),
    "DeleteObjectCount":    ("DeleteObject成功请求数",    "Count"),
    "DeleteObjectsCount":   ("DeleteObjects成功请求数",   "Count"),
}
# 全量合并（供默认采集使用）
OSS_METRICS = {
    **OSS_METRICS_OVERVIEW,
    **OSS_METRICS_REQUEST,
    **OSS_METRICS_LATENCY,
    **OSS_METRICS_OPS,
}

# MQ Namespace: acs_rocketmq_dashboard  周期: 60s
# 实例级指标  维度: userId, instanceId
MQ_INSTANCE_METRICS = {
    "MessageRetentionPeriod":          ("消息保留时长",          "hour"),
    "SendMessageCountPerInstance":     ("生产者每分钟发送消息数", "Count/min"),
    "ReceiveMessageCountPerInstance":  ("消费者每分钟接收消息数", "Count/min"),
    "SendMessageTPSPerInstance":       ("生产者发送TPS",          "Count/min"),
    "ReceiveMessageTPSPerInstance":    ("消费者接收TPS",          "Count/min"),
}

# GroupID 级指标  维度: userId, instanceId, groupId
MQ_GROUP_METRICS = {
    "ConsumerLag":               ("消息堆积量",               "Count"),
    "ReceiveMessageCountPerGid": ("消费者每分钟接收消息数",    "Count/min"),
    "SendMessageCountPerGid":    ("生产者每分钟发送消息数",    "Count/min"),
    "SendDLQMessageCountPerGid": ("每分钟死信消息数",          "Count/min"),
    "ReceiveMessageTPSPerGid":   ("消费者接收TPS",             "Count/min"),
    "SendMessageTPSPerGid":      ("生产者发送TPS",             "Count/min"),
}

# Topic 级指标  维度: userId, instanceId, topic
MQ_TOPIC_METRICS = {
    "ReceiveMessageCountPerTopic": ("消费者每分钟接收消息数",  "Count/min"),
    "SendMessageCountPerTopic":    ("生产者每分钟发送消息数",  "Count/min"),
    "ReceiveMessageTPSPerTopic":   ("消费者接收TPS",           "Count/min"),
    "SendMessageTPSPerTopic":      ("生产者发送TPS",           "Count/min"),
}

# GroupID+Topic 级指标  维度: userId, instanceId, groupId, topic
MQ_GID_TOPIC_METRICS = {
    "ConsumerLagPerGidTopic":            ("消息堆积量",               "Count"),
    "ReceiveMessageCountPerGidTopic":    ("消费者每分钟接收消息数",    "Count/min"),
    "SendDLQMessageCountPerGidTopic":    ("每分钟死信消息数",          "Count/min"),
    "SendMessageCountPerGidTopic":       ("生产者每分钟发送消息数",    "Count/min"),
}

# Namespace 常量
OSS_NS = "acs_oss_dashboard"
MQ_NS  = "acs_rocketmq_dashboard"

# ══════════════════════════════════════════════════════════════════════════════
# § 3  签名与 HTTP 核心
# ══════════════════════════════════════════════════════════════════════════════

DEBUG = False  # 运行时由 --debug 参数控制，开启后打印完整请求 URL 和响应体


def _sign(params: dict) -> str:
    """
    阿里云 API 签名算法（SignatureVersion=1.0，HMAC-SHA1）
    步骤：
      1. 将所有参数按 key 字母序排列
      2. URL 编码每个 key 和 value（RFC 3986，空格编码为 %20）
      3. 拼接成 key=value&key=value 形式的查询串
      4. 构造待签名字符串：GET&%2F&{对查询串再次编码}
      5. 用 (AccessKeySecret + "&") 作为密钥做 HMAC-SHA1，再 Base64 编码
    """
    def enc(s):
        return urllib.parse.quote(str(s), safe="")

    sorted_query = "&".join(f"{enc(k)}={enc(v)}" for k, v in sorted(params.items()))
    string_to_sign = f"GET&{enc('/')}&{enc(sorted_query)}"
    key = (ACCESS_KEY_SECRET + "&").encode()
    digest = hmac.new(key, string_to_sign.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def call_api(action: str, extra: dict = None) -> dict:
    """
    发起一次云监控 API 调用，返回解析后的 JSON 字典。

    参数说明（来自开发手册"公共请求参数"）：
      Action           — 接口名，如 DescribeMetricLast
      Product          — 固定为 Cms
      Version          — 固定为 2019-01-01
      RegionId         — 环境 Region
      AccessKeyId      — AK
      SignatureMethod  — 固定 HMAC-SHA1
      SignatureVersion — 固定 1.0
      SignatureNonce   — 随机串，防重放
      Timestamp        — UTC 时间，ISO8601 格式
      Format           — 固定 JSON
      Signature        — 由 _sign() 计算
    """
    params = {
        "Action":           action,
        "Product":          "Cms",
        "Version":          "2019-01-01",
        "RegionId":         REGION_ID,
        "AccessKeyId":      ACCESS_KEY_ID,
        "SignatureMethod":  "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce":   uuid.uuid4().hex,   # 不含连字符的随机 UUID
        "Timestamp":        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Format":           "JSON",
    }
    if extra:
        params.update(extra)
    params["Signature"] = _sign(params)

    url = f"{API_ENDPOINT}/?{urllib.parse.urlencode(params)}"

    # 专有云公共 Header（开发手册"公共Header参数"）
    headers = {k: v for k, v in {
        "x-acs-regionid":        REGION_ID,
        "x-acs-organizationid":  ORG_ID,
        "x-acs-resourcegroupid": RESOURCE_GROUP_ID,
        "x-acs-instanceid":      INSTANCE_ID,
    }.items() if v}  # 只保留非空项

    if DEBUG:
        print(f"\n[DEBUG] GET {url}")
        for k, v in headers.items():
            print(f"[DEBUG] Header: {k}: {v}")

    # 专有云通常使用自签证书，关闭 SSL 校验避免证书错误
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            body = resp.read().decode()
            if DEBUG:
                print(f"[DEBUG] Response:\n{json.dumps(json.loads(body), ensure_ascii=False, indent=2)}\n")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode(errors='replace')}") from e


# ══════════════════════════════════════════════════════════════════════════════
# § 4  CMS API 封装
# ══════════════════════════════════════════════════════════════════════════════

def list_projects(page_size=100) -> list:
    """
    DescribeProjectMeta — 查询云监控支持的所有云产品列表
    返回字段：Namespace（命名空间）、Description（产品说明）、Labels
    """
    r = call_api("DescribeProjectMeta", {"PageSize": str(page_size)})
    return r.get("Resources", {}).get("Resource", [])


def list_metric_meta(namespace: str, metric_name: str = None, page_size=200) -> list:
    """
    DescribeMetricMetaList — 查询指定 Namespace 下所有监控项定义
    返回字段：MetricName、Description、Unit、Periods、Statistics、Dimensions
    metric_name 不为空时按指标名精确过滤
    """
    extra = {"Namespace": namespace, "PageSize": str(page_size)}
    if metric_name:
        extra["MetricName"] = metric_name
    r = call_api("DescribeMetricMetaList", extra)
    return r.get("Resources", {}).get("Resource", [])


def get_metric_last(namespace: str, metric_name: str,
                    dimensions: dict = None, period=60) -> list:
    """
    DescribeMetricLast — 查询监控项的最新数据点
    - dimensions 为 None 时不传 Dimensions 参数，API 会返回该指标下
      所有资源的最新数据，利用这个特性可以枚举出所有资源实例。
    - dimensions 指定时只返回该资源的数据。
    返回数据点列表，每个数据点含 timestamp/Average/Maximum/Minimum 等字段
    """
    extra = {"Namespace": namespace, "MetricName": metric_name, "Period": str(period)}
    if dimensions:
        # Dimensions 是 JSON 字符串，格式为 [{"key":"value", ...}]
        extra["Dimensions"] = json.dumps([dimensions])
    r = call_api("DescribeMetricLast", extra)
    raw = r.get("Datapoints", "[]")
    return json.loads(raw) if isinstance(raw, str) else raw


def get_metric_list(namespace: str, metric_name: str, dimensions: dict,
                    start_time=None, end_time=None, period=60) -> list:
    """
    DescribeMetricList — 查询时间段内的历史监控数据（自动翻页）
    start_time/end_time：Unix 时间戳（秒）或 'YYYY-MM-DD HH:MM:SS'，默认过去 1 小时
    返回该时间段内所有数据点的列表
    """
    now = int(time.time())
    extra = {
        "Namespace":  namespace,
        "MetricName": metric_name,
        "Dimensions": json.dumps([dimensions]),
        "StartTime":  str(start_time or now - 3600),
        "EndTime":    str(end_time or now),
        "Period":     str(period),
        "Length":     "1000",  # 每页最大 1000 条
    }
    points = []
    while True:
        r = call_api("DescribeMetricList", extra)
        raw = r.get("Datapoints", "[]")
        points.extend(json.loads(raw) if isinstance(raw, str) else raw)
        token = r.get("NextToken")
        if not token:
            break
        extra["NextToken"] = token  # 有 NextToken 则继续翻页
    return points


# ══════════════════════════════════════════════════════════════════════════════
# § 5  资源发现
#   原理：DescribeMetricLast 不传 Dimensions 时返回全量资源数据，
#         从数据点中提取维度字段并去重，即得到资源列表。
# ══════════════════════════════════════════════════════════════════════════════

def _dedup(points: list, *keys) -> list:
    """从数据点列表中按指定字段组合去重，返回唯一资源列表"""
    seen, result = set(), []
    for p in points:
        combo = tuple(p.get(k, "") for k in keys)
        if combo not in seen:
            seen.add(combo)
            result.append({k: p.get(k, "") for k in keys})
    return result


def list_mq_instances() -> list:
    """通过实例级指标不传 Dimensions，从返回数据中提取所有 MQ 实例 ID"""
    return _dedup(get_metric_last(MQ_NS, "SendMessageCountPerInstance"), "userId", "instanceId")


def list_mq_groups(instance_id: str, user_id: str = None) -> list:
    """通过 ConsumerLag 指标提取指定实例下所有消费者 GroupID"""
    dims = {"instanceId": instance_id}
    if user_id:
        dims["userId"] = user_id
    return _dedup(get_metric_last(MQ_NS, "ConsumerLag", dims), "userId", "instanceId", "groupId")


def list_mq_topics(instance_id: str, user_id: str = None) -> list:
    """通过 Topic 级指标提取指定实例下所有 Topic"""
    dims = {"instanceId": instance_id}
    if user_id:
        dims["userId"] = user_id
    return _dedup(get_metric_last(MQ_NS, "SendMessageCountPerTopic", dims), "userId", "instanceId", "topic")


def list_oss_buckets(user_id: str = None) -> list:
    """通过请求数指标提取所有 OSS Bucket 名称（只有近期有流量的 Bucket 才会出现）"""
    dims = {"userId": user_id} if user_id else None
    return _dedup(get_metric_last(OSS_NS, "TotalRequestCount", dims), "userId", "BucketName")


# ══════════════════════════════════════════════════════════════════════════════
# § 6  监控数据采集
# ══════════════════════════════════════════════════════════════════════════════

def collect_latest(namespace: str, metric_map: dict, dimensions: dict, period=60) -> dict:
    """
    通用：批量采集一组指标的最新值
    metric_map 格式：{ MetricName: (中文说明, 单位) }
    返回：{ MetricName: 数据点 dict 或 {"error": "..."} 或 None }
    """
    result = {}
    for metric in metric_map:
        try:
            points = get_metric_last(namespace, metric, dimensions, period)
            result[metric] = points[-1] if points else None
        except Exception as e:
            result[metric] = {"error": str(e)}
    return result


def collect_history(namespace: str, metric_name: str, dimensions: dict,
                    start_time=None, end_time=None, period=60) -> list:
    """通用：采集单个指标的历史时序数据"""
    return get_metric_list(namespace, metric_name, dimensions, start_time, end_time, period)


# ══════════════════════════════════════════════════════════════════════════════
# § 7  输出辅助
# ══════════════════════════════════════════════════════════════════════════════

def _ts(ms) -> str:
    """毫秒时间戳 → 可读时间字符串"""
    try:
        return datetime.datetime.fromtimestamp(int(ms) / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ms)


def _val(point: dict) -> str:
    """从数据点取值，优先 Average，其次 Value/Maximum"""
    return str(point.get("Average", point.get("Value", point.get("Maximum", "-"))))


def _print_metrics(data: dict, metric_map: dict):
    """打印批量采集结果"""
    for name, point in data.items():
        desc, unit = metric_map.get(name, ("", ""))
        label = f"{name:<50} {desc:<22}"
        if point is None:
            print(f"  {label} (暂无数据)")
        elif "error" in point:
            print(f"  {label} 错误: {point['error']}")
        else:
            print(f"  {label} = {_val(point)} {unit}  [{_ts(point.get('timestamp',0))}]")


def _print_datapoints(points: list, metric_name: str):
    """打印历史数据点列表"""
    print(f"\n指标: {metric_name}，共 {len(points)} 个数据点")
    for p in points:
        print(f"  [{_ts(p.get('timestamp',0))}]  "
              f"Average={p.get('Average','-')}  "
              f"Maximum={p.get('Maximum','-')}  "
              f"Minimum={p.get('Minimum','-')}")


# ══════════════════════════════════════════════════════════════════════════════
# § 8  接口自测
# ══════════════════════════════════════════════════════════════════════════════

def cmd_test():
    """连通性自测：依次测试 CMS 基础接口和 OSS/MQ 指标元数据接口"""
    print("=" * 62)
    print("接口连通性测试")
    print(f"  Endpoint : {API_ENDPOINT}")
    print(f"  Region   : {REGION_ID}")
    print(f"  AK       : {ACCESS_KEY_ID[:6]}***")
    print("-" * 62)

    # 1. 测试 DescribeProjectMeta（最基础的接口，不需要额外参数）
    try:
        projects = list_projects(page_size=5)
        print(f"✓ DescribeProjectMeta OK — 返回 {len(projects)} 个产品（前3个）")
        for p in projects[:3]:
            print(f"    {p.get('Namespace',''):<35} {p.get('Description','')}")
    except Exception as e:
        print(f"✗ DescribeProjectMeta 失败: {e}")
        print("  → 请检查 API_ENDPOINT 是否可达、AK/SK 是否正确")
        return

    # 2. 测试 OSS 和 MQ 的指标元数据接口
    for ns, label in [(OSS_NS, "OSS"), (MQ_NS, "MQ")]:
        try:
            metas = list_metric_meta(ns, page_size=3)
            print(f"✓ DescribeMetricMetaList [{label}] OK — 前3项指标:")
            for m in metas[:3]:
                print(f"    {m.get('MetricName',''):<45} [{m.get('Unit','')}]")
        except Exception as e:
            print(f"✗ DescribeMetricMetaList [{label}] 失败: {e}")

    print("=" * 62)


# ══════════════════════════════════════════════════════════════════════════════
# § 9  CLI
# ══════════════════════════════════════════════════════════════════════════════

USAGE = """
使用示例:

  # 接口连通性自测（第一步必做）
  python cms_monitor.py test

  # 资源列表（不指定 Dimensions，从监控数据中枚举所有资源）
  python cms_monitor.py list-mq-instances
  python cms_monitor.py list-mq-groups   --instance MQ_INST_xxx
  python cms_monitor.py list-mq-topics   --instance MQ_INST_xxx
  python cms_monitor.py list-oss-buckets

  # 查看支持的产品和监控项定义
  python cms_monitor.py list-projects
  python cms_monitor.py list-metrics --ns acs_oss_dashboard
  python cms_monitor.py list-metrics --ns acs_rocketmq_dashboard

  # 采集最新指标值
  python cms_monitor.py oss-metrics   --bucket my-bucket --uid 123456
  python cms_monitor.py oss-metrics   --bucket my-bucket --uid 123456 --category overview
  python cms_monitor.py oss-metrics   --bucket my-bucket --uid 123456 --category request
  python cms_monitor.py oss-metrics   --bucket my-bucket --uid 123456 --category latency
  python cms_monitor.py oss-metrics   --bucket my-bucket --uid 123456 --category ops
  python cms_monitor.py mq-instance   --instance MQ_INST_xxx --uid 123456
  python cms_monitor.py mq-group      --instance MQ_INST_xxx --group GID_xxx --uid 123456
  python cms_monitor.py mq-topic      --instance MQ_INST_xxx --topic TopicA  --uid 123456
  python cms_monitor.py mq-gid-topic  --instance MQ_INST_xxx --group GID_xxx --topic TopicA --uid 123456

  # 采集历史时序数据（默认过去1小时，可用 --start/--end 指定范围）
  python cms_monitor.py oss-history --bucket my-bucket --uid 123456 --metric Availability
  python cms_monitor.py mq-history  --instance MQ_INST_xxx --uid 123456 --metric ConsumerLag --group GID_xxx

  # 单指标连通性验证（调试用）
  python cms_monitor.py test-oss --bucket my-bucket  --uid 123456
  python cms_monitor.py test-mq  --instance MQ_INST_xxx --uid 123456

  # 调试模式：打印完整 HTTP 请求 URL 和原始响应
  python cms_monitor.py --debug test
  python cms_monitor.py --debug list-mq-instances
"""


def _parser():
    p = argparse.ArgumentParser(
        description="阿里云飞天专有云 云监控 MQ/OSS 采集脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE,
    )
    p.add_argument("--debug", action="store_true",
                   help="打印完整 HTTP 请求 URL 和原始响应（排查签名/网络问题）")
    s = p.add_subparsers(dest="cmd", required=True)

    # ── 自测 ────────────────────────────────────────────────────────────────
    s.add_parser("test",          help="接口连通性与 AK/SK 自测")

    # ── 资源列表 ─────────────────────────────────────────────────────────────
    p1 = s.add_parser("list-mq-instances", help="列出所有 MQ 实例")
    p1.add_argument("--uid", default=None, help="可选：按 userId 过滤")

    p2 = s.add_parser("list-mq-groups",   help="列出指定 MQ 实例下所有 GroupID")
    p2.add_argument("--instance", required=True)
    p2.add_argument("--uid",      default=None)

    p3 = s.add_parser("list-mq-topics",   help="列出指定 MQ 实例下所有 Topic")
    p3.add_argument("--instance", required=True)
    p3.add_argument("--uid",      default=None)

    p4 = s.add_parser("list-oss-buckets", help="列出所有 OSS Bucket")
    p4.add_argument("--uid", default=None)

    # ── 元数据 ───────────────────────────────────────────────────────────────
    s.add_parser("list-projects", help="列出云监控支持的所有产品")

    p5 = s.add_parser("list-metrics", help="列出指定 Namespace 的监控项定义")
    p5.add_argument("--ns",     required=True, help="如 acs_oss_dashboard")
    p5.add_argument("--metric", default=None,  help="按指标名过滤")

    # ── 最新指标采集 ──────────────────────────────────────────────────────────
    p6 = s.add_parser("oss-metrics",  help="采集 OSS Bucket 最新指标")
    p6.add_argument("--bucket",    required=True)
    p6.add_argument("--uid",       required=True)
    p6.add_argument("--metrics",   default=None, help="逗号分隔指标名，默认全部")
    p6.add_argument("--category",  default=None,
                    help="按分类采集：overview/request/latency/ops，默认全部")
    p6.add_argument("--period",    type=int, default=60)

    p7 = s.add_parser("mq-instance", help="采集 MQ 实例级最新指标")
    p7.add_argument("--instance", required=True)
    p7.add_argument("--uid",      required=True)
    p7.add_argument("--metrics",  default=None)
    p7.add_argument("--period",   type=int, default=60)

    p8 = s.add_parser("mq-group",    help="采集 MQ GroupID 级最新指标（含消息堆积）")
    p8.add_argument("--instance", required=True)
    p8.add_argument("--group",    required=True)
    p8.add_argument("--uid",      required=True)
    p8.add_argument("--metrics",  default=None)
    p8.add_argument("--period",   type=int, default=60)

    p9 = s.add_parser("mq-topic",    help="采集 MQ Topic 级最新指标")
    p9.add_argument("--instance", required=True)
    p9.add_argument("--topic",    required=True)
    p9.add_argument("--uid",      required=True)
    p9.add_argument("--metrics",  default=None)
    p9.add_argument("--period",   type=int, default=60)

    pgt = s.add_parser("mq-gid-topic", help="采集 MQ GroupID+Topic 级最新指标（消息堆积精细维度）")
    pgt.add_argument("--instance", required=True)
    pgt.add_argument("--group",    required=True)
    pgt.add_argument("--topic",    required=True)
    pgt.add_argument("--uid",      required=True)
    pgt.add_argument("--metrics",  default=None)
    pgt.add_argument("--period",   type=int, default=60)

    # ── 历史时序采集 ──────────────────────────────────────────────────────────
    pa = s.add_parser("oss-history",  help="采集 OSS 历史时序数据")
    pa.add_argument("--bucket",  required=True)
    pa.add_argument("--uid",     required=True)
    pa.add_argument("--metric",  required=True)
    pa.add_argument("--start",   default=None, help="Unix 时间戳(秒) 或 YYYY-MM-DD HH:MM:SS")
    pa.add_argument("--end",     default=None)
    pa.add_argument("--period",  type=int, default=60)

    pb = s.add_parser("mq-history",   help="采集 MQ 历史时序数据")
    pb.add_argument("--instance", required=True)
    pb.add_argument("--uid",      required=True)
    pb.add_argument("--metric",   required=True)
    pb.add_argument("--group",    default=None, help="可选：GroupID 维度")
    pb.add_argument("--topic",    default=None, help="可选：Topic 维度")
    pb.add_argument("--start",    default=None)
    pb.add_argument("--end",      default=None)
    pb.add_argument("--period",   type=int, default=60)

    # ── 单指标调试 ────────────────────────────────────────────────────────────
    pc = s.add_parser("test-oss", help="测试 OSS 单指标采集连通性")
    pc.add_argument("--bucket", required=True)
    pc.add_argument("--uid",    required=True)
    pc.add_argument("--metric", default="Availability")

    pd = s.add_parser("test-mq", help="测试 MQ 单指标采集连通性")
    pd.add_argument("--instance", required=True)
    pd.add_argument("--uid",      required=True)
    pd.add_argument("--metric",   default="SendMessageCountPerInstance")

    return p


def main():
    args = _parser().parse_args()

    global DEBUG
    DEBUG = args.debug

    # ── 自测 ─────────────────────────────────────────────────────────────────
    if args.cmd == "test":
        cmd_test()

    # ── 资源列表 ──────────────────────────────────────────────────────────────
    elif args.cmd == "list-mq-instances":
        rows = list_mq_instances()
        if args.uid:
            rows = [r for r in rows if r.get("userId") == args.uid]
        print(f"MQ 实例共 {len(rows)} 个:")
        for r in rows:
            print(f"  userId={r.get('userId',''):<20}  instanceId={r.get('instanceId','')}")

    elif args.cmd == "list-mq-groups":
        rows = list_mq_groups(args.instance, args.uid)
        print(f"实例 {args.instance} 下 GroupID 共 {len(rows)} 个:")
        for r in rows:
            print(f"  userId={r.get('userId',''):<20}  groupId={r.get('groupId','')}")

    elif args.cmd == "list-mq-topics":
        rows = list_mq_topics(args.instance, args.uid)
        print(f"实例 {args.instance} 下 Topic 共 {len(rows)} 个:")
        for r in rows:
            print(f"  userId={r.get('userId',''):<20}  topic={r.get('topic','')}")

    elif args.cmd == "list-oss-buckets":
        rows = list_oss_buckets(args.uid)
        print(f"OSS Bucket 共 {len(rows)} 个:")
        for r in rows:
            print(f"  userId={r.get('userId',''):<20}  BucketName={r.get('BucketName','')}")

    # ── 元数据 ────────────────────────────────────────────────────────────────
    elif args.cmd == "list-projects":
        rows = list_projects(page_size=200)
        print(f"云监控支持产品共 {len(rows)} 个:")
        for r in rows:
            print(f"  {r.get('Namespace',''):<40} {r.get('Description','')}")

    elif args.cmd == "list-metrics":
        rows = list_metric_meta(args.ns, args.metric)
        print(f"Namespace [{args.ns}] 监控项共 {len(rows)} 个:")
        for r in rows:
            print(f"  {r.get('MetricName',''):<50} {r.get('Description',''):<28} "
                  f"Unit={r.get('Unit',''):<12} Periods={r.get('Periods','')}")

    # ── 最新指标采集 ──────────────────────────────────────────────────────────
    elif args.cmd == "oss-metrics":
        # 按分类选取指标子集，方便按需采集而不是一次全量（共50+个指标）
        _cat_map = {
            "overview": OSS_METRICS_OVERVIEW,
            "request":  OSS_METRICS_REQUEST,
            "latency":  OSS_METRICS_LATENCY,
            "ops":      OSS_METRICS_OPS,
        }
        base = _cat_map.get(args.category, OSS_METRICS) if args.category else OSS_METRICS
        mmap = {k: v for k, v in base.items()
                if not args.metrics or k in args.metrics.split(",")}
        dims = {"userId": args.uid, "BucketName": args.bucket}
        cat_label = f"[{args.category}]" if args.category else "[全部]"
        print(f"\nOSS Bucket: {args.bucket}  类别: {cat_label}")
        _print_metrics(collect_latest(OSS_NS, mmap, dims, args.period), mmap)

    elif args.cmd == "mq-instance":
        mmap = {k: v for k, v in MQ_INSTANCE_METRICS.items()
                if not args.metrics or k in args.metrics.split(",")}
        dims = {"userId": args.uid, "instanceId": args.instance}
        print(f"\nMQ 实例: {args.instance}")
        _print_metrics(collect_latest(MQ_NS, mmap, dims, args.period), mmap)

    elif args.cmd == "mq-group":
        mmap = {k: v for k, v in MQ_GROUP_METRICS.items()
                if not args.metrics or k in args.metrics.split(",")}
        dims = {"userId": args.uid, "instanceId": args.instance, "groupId": args.group}
        print(f"\nMQ Group: {args.group}  (实例: {args.instance})")
        _print_metrics(collect_latest(MQ_NS, mmap, dims, args.period), mmap)

    elif args.cmd == "mq-topic":
        mmap = {k: v for k, v in MQ_TOPIC_METRICS.items()
                if not args.metrics or k in args.metrics.split(",")}
        dims = {"userId": args.uid, "instanceId": args.instance, "topic": args.topic}
        print(f"\nMQ Topic: {args.topic}  (实例: {args.instance})")
        _print_metrics(collect_latest(MQ_NS, mmap, dims, args.period), mmap)

    elif args.cmd == "mq-gid-topic":
        mmap = {k: v for k, v in MQ_GID_TOPIC_METRICS.items()
                if not args.metrics or k in args.metrics.split(",")}
        dims = {"userId": args.uid, "instanceId": args.instance,
                "groupId": args.group, "topic": args.topic}
        print(f"\nMQ GroupID+Topic: group={args.group}  topic={args.topic}  (实例: {args.instance})")
        _print_metrics(collect_latest(MQ_NS, mmap, dims, args.period), mmap)

    # ── 历史时序采集 ──────────────────────────────────────────────────────────
    elif args.cmd == "oss-history":
        dims = {"userId": args.uid, "BucketName": args.bucket}
        pts = collect_history(OSS_NS, args.metric, dims, args.start, args.end, args.period)
        _print_datapoints(pts, args.metric)

    elif args.cmd == "mq-history":
        dims = {"userId": args.uid, "instanceId": args.instance}
        if args.group: dims["groupId"] = args.group
        if args.topic: dims["topic"]   = args.topic
        pts = collect_history(MQ_NS, args.metric, dims, args.start, args.end, args.period)
        _print_datapoints(pts, args.metric)

    # ── 单指标调试 ────────────────────────────────────────────────────────────
    elif args.cmd == "test-oss":
        dims = {"userId": args.uid, "BucketName": args.bucket}
        print(f"OSS 指标测试: bucket={args.bucket}  metric={args.metric}")
        try:
            pts = get_metric_last(OSS_NS, args.metric, dims)
            print(f"  最新数据点: {json.dumps(pts[-1], ensure_ascii=False)}" if pts else "  暂无数据")
        except Exception as e:
            print(f"  错误: {e}")

    elif args.cmd == "test-mq":
        dims = {"userId": args.uid, "instanceId": args.instance}
        print(f"MQ 指标测试: instance={args.instance}  metric={args.metric}")
        try:
            pts = get_metric_last(MQ_NS, args.metric, dims)
            print(f"  最新数据点: {json.dumps(pts[-1], ensure_ascii=False)}" if pts else "  暂无数据")
        except Exception as e:
            print(f"  错误: {e}")


if __name__ == "__main__":
    main()
