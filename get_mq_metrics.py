#!/usr/bin/env python3
"""
MQ 消息队列（RocketMQ）指标采集脚本
从环境变量读取配置，查询指定实例的所有最新监控指标，以扁平 JSON 输出。

必填环境变量:
  CMS_ENDPOINT        — 云监控 API 地址，如 https://cms.cn-hangzhou.example.com
  ACCESS_KEY_ID       — 阿里云 AccessKey ID
  ACCESS_KEY_SECRET   — 阿里云 AccessKey Secret
  REGION_ID           — Region，如 cn-hangzhou
  MQ_INSTANCE_ID      — 目标 MQ 实例 ID，如 MQ_INST_xxx

可选环境变量:
  MQ_GROUP_ID         — 消费者 GroupID（填写后追加采集 Group 级指标）
  MQ_TOPIC            — Topic 名称（填写后追加采集 Topic 级指标）
                        MQ_GROUP_ID 与 MQ_TOPIC 同时填写时，
                        还会采集 GroupID+Topic 级联合指标
  ORG_ID              — 专有云组织 ID（x-acs-organizationid）
  RESOURCE_GROUP_ID   — 专有云资源集 ID（x-acs-resourcegroupid）
  PERIOD              — 采集周期（秒），默认 60

Key 命名规则（扁平 JSON）:
  实例级指标          → MetricName
  Group 级指标        → MetricName__group_<GroupID>
  Topic 级指标        → MetricName__topic_<Topic>
  Group+Topic 级指标  → MetricName__group_<GroupID>__topic_<Topic>

输出示例:
  {
    "MessageRetentionPeriod": 72,
    "SendMessageCountPerInstance": 1000,
    "ConsumerLag__group_GID_test": 0,
    "SendMessageCountPerTopic__topic_TopicA": 300,
    "_meta": { ... }
  }
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import ssl
import sys
import uuid
import urllib.parse
import urllib.request

# ── 从环境变量加载配置 ────────────────────────────────────────────────────────
def _require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        print(json.dumps({"error": f"缺少必填环境变量: {name}"}, ensure_ascii=False))
        sys.exit(1)
    return val


API_ENDPOINT      = _require_env("CMS_ENDPOINT").rstrip("/")
ACCESS_KEY_ID     = _require_env("ACCESS_KEY_ID")
ACCESS_KEY_SECRET = _require_env("ACCESS_KEY_SECRET")
REGION_ID         = _require_env("REGION_ID")
MQ_INSTANCE_ID    = _require_env("MQ_INSTANCE_ID")

MQ_GROUP_ID       = os.environ.get("MQ_GROUP_ID", "").strip()
MQ_TOPIC          = os.environ.get("MQ_TOPIC", "").strip()
ORG_ID            = os.environ.get("ORG_ID", "").strip()
RESOURCE_GROUP_ID = os.environ.get("RESOURCE_GROUP_ID", "").strip()
PERIOD            = int(os.environ.get("PERIOD", "60"))

# ── MQ 监控项定义（Namespace: acs_rocketmq_dashboard，周期 60s）───────────────

# 实例级指标  维度: userId, instanceId
MQ_INSTANCE_METRICS = {
    "MessageRetentionPeriod":          ("消息保留时长",           "hour"),
    "SendMessageCountPerInstance":     ("生产者每分钟发送消息数",  "Count/min"),
    "ReceiveMessageCountPerInstance":  ("消费者每分钟接收消息数",  "Count/min"),
    "SendMessageTPSPerInstance":       ("生产者发送TPS",           "Count/min"),
    "ReceiveMessageTPSPerInstance":    ("消费者接收TPS",           "Count/min"),
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

MQ_NAMESPACE = "acs_rocketmq_dashboard"

# ── 签名与 HTTP ───────────────────────────────────────────────────────────────

def _sign(params: dict) -> str:
    """阿里云 API HMAC-SHA1 签名"""
    def enc(s):
        return urllib.parse.quote(str(s), safe="")

    sorted_query = "&".join(f"{enc(k)}={enc(v)}" for k, v in sorted(params.items()))
    string_to_sign = f"GET&{enc('/')}&{enc(sorted_query)}"
    key = (ACCESS_KEY_SECRET + "&").encode()
    digest = hmac.new(key, string_to_sign.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def _call_api(action: str, extra: dict = None) -> dict:
    params = {
        "Action":           action,
        "Product":          "Cms",
        "Version":          "2019-01-01",
        "RegionId":         REGION_ID,
        "AccessKeyId":      ACCESS_KEY_ID,
        "SignatureMethod":  "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce":   uuid.uuid4().hex,
        "Timestamp":        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Format":           "JSON",
    }
    if extra:
        params.update(extra)
    params["Signature"] = _sign(params)

    url = f"{API_ENDPOINT}/?{urllib.parse.urlencode(params)}"
    headers = {k: v for k, v in {
        "x-acs-regionid":        REGION_ID,
        "x-acs-organizationid":  ORG_ID,
        "x-acs-resourcegroupid": RESOURCE_GROUP_ID,
    }.items() if v}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode(errors='replace')}") from e


def _get_metric_last(metric_name: str, dimensions: dict) -> list:
    extra = {
        "Namespace":  MQ_NAMESPACE,
        "MetricName": metric_name,
        "Period":     str(PERIOD),
        "Dimensions": json.dumps([dimensions]),
    }
    r = _call_api("DescribeMetricLast", extra)
    raw = r.get("Datapoints", "[]")
    return json.loads(raw) if isinstance(raw, str) else raw


def _extract_value(point: dict):
    """从数据点中提取数值，优先 Average，其次 Value / Maximum"""
    for key in ("Average", "Value", "Maximum"):
        if key in point and point[key] is not None:
            return point[key]
    return None


def _collect(metric_map: dict, dimensions: dict, key_prefix: str, result: dict):
    """批量采集一组指标并写入 result，Key 格式为 MetricName<key_prefix>"""
    for metric_name in metric_map:
        flat_key = f"{metric_name}{key_prefix}" if key_prefix else metric_name
        try:
            points = _get_metric_last(metric_name, dimensions)
            result[flat_key] = _extract_value(points[-1]) if points else None
        except Exception as e:
            result[flat_key] = f"ERROR: {e}"


# ── 主逻辑 ────────────────────────────────────────────────────────────────────

def main():
    result = {}

    # 实例级指标（必采）
    inst_dims = {"instanceId": MQ_INSTANCE_ID}
    _collect(MQ_INSTANCE_METRICS, inst_dims, "", result)

    # Group 级指标（MQ_GROUP_ID 非空时采集）
    if MQ_GROUP_ID:
        group_dims = {"instanceId": MQ_INSTANCE_ID, "groupId": MQ_GROUP_ID}
        _collect(MQ_GROUP_METRICS, group_dims, f"__group_{MQ_GROUP_ID}", result)

    # Topic 级指标（MQ_TOPIC 非空时采集）
    if MQ_TOPIC:
        topic_dims = {"instanceId": MQ_INSTANCE_ID, "topic": MQ_TOPIC}
        _collect(MQ_TOPIC_METRICS, topic_dims, f"__topic_{MQ_TOPIC}", result)

    # GroupID+Topic 级指标（两者均非空时采集）
    if MQ_GROUP_ID and MQ_TOPIC:
        gid_topic_dims = {
            "instanceId": MQ_INSTANCE_ID,
            "groupId":    MQ_GROUP_ID,
            "topic":      MQ_TOPIC,
        }
        _collect(
            MQ_GID_TOPIC_METRICS,
            gid_topic_dims,
            f"__group_{MQ_GROUP_ID}__topic_{MQ_TOPIC}",
            result,
        )

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
