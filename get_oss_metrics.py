#!/usr/bin/env python3
"""
OSS 对象存储指标采集脚本
从环境变量读取配置，查询指定 Bucket 的所有最新监控指标，以扁平 JSON 输出。

必填环境变量:
  CMS_ENDPOINT        — 云监控 API 地址，如 https://cms.cn-hangzhou.example.com
  ACCESS_KEY_ID       — 阿里云 AccessKey ID
  ACCESS_KEY_SECRET   — 阿里云 AccessKey Secret
  REGION_ID           — Region，如 cn-hangzhou
  OSS_BUCKET_NAME     — 目标 OSS Bucket 名称

可选环境变量:
  ORG_ID              — 专有云组织 ID（x-acs-organizationid）
  RESOURCE_GROUP_ID   — 专有云资源集 ID（x-acs-resourcegroupid）
  PERIOD              — 采集周期（秒），默认 60

输出示例:
  {
    "Availability": 99.95,
    "TotalRequestCount": 12345,
    "InternetSend": 1048576,
    ...
    "_meta": {
      "bucket": "my-bucket",
      "collected_at": "2026-03-06T10:00:00Z"
    }
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
OSS_BUCKET_NAME   = _require_env("OSS_BUCKET_NAME")

ORG_ID            = os.environ.get("ORG_ID", "").strip()
RESOURCE_GROUP_ID = os.environ.get("RESOURCE_GROUP_ID", "").strip()
PERIOD            = int(os.environ.get("PERIOD", "60"))

# ── OSS 监控项定义（Namespace: acs_oss_dashboard，周期 60s）──────────────────
OSS_METRICS = {
    # 服务总览
    "Availability":                      ("可用性",                    "%"),
    "RequestValidRate":                  ("有效请求率",                 "%"),
    "TotalRequestCount":                 ("总请求数",                   "Count"),
    "ValidRequestCount":                 ("有效请求数",                  "Count"),
    "InternetSend":                      ("公网流出流量",                "Bytes"),
    "InternetRecv":                      ("公网流入流量",                "Bytes"),
    "IntranetSend":                      ("内网流出流量",                "Bytes"),
    "IntranetRecv":                      ("内网流入流量",                "Bytes"),
    "CdnSend":                           ("CDN流出流量",                 "Bytes"),
    "CdnRecv":                           ("CDN流入流量",                 "Bytes"),
    "SyncSend":                          ("跨区域复制流出流量",           "Bytes"),
    "SyncRecv":                          ("跨区域复制流入流量",           "Bytes"),
    "MeteringStorageUtilization":        ("存储大小",                   "Bytes"),
    "MeteringStorageUtilizationGB":      ("存储大小GB",                  "Gbytes"),
    "MeteringStorageUtilizationPercent": ("存储使用率",                  "%"),
    # 请求状态详情
    "ServerErrorCount":                  ("服务端错误请求数",             "Count"),
    "ServerErrorRate":                   ("服务端错误请求占比",           "%"),
    "NetworkErrorCount":                 ("网络错误请求数",               "Count"),
    "NetworkErrorRate":                  ("网络错误请求占比",             "%"),
    "AuthorizationErrorCount":           ("客户端授权错误请求数",          "Count"),
    "AuthorizationErrorRate":            ("客户端授权错误请求占比",        "%"),
    "ResourceNotFoundErrorCount":        ("客户端资源不存在错误请求数",    "Count"),
    "ResourceNotFoundErrorRate":         ("客户端资源不存在错误占比",      "%"),
    "ClientTimeoutErrorCount":           ("客户端超时错误请求数",          "Count"),
    "ClientTimeoutErrorRate":            ("客户端超时错误请求占比",        "%"),
    "ClientOtherErrorCount":             ("客户端其他错误请求数",          "Count"),
    "ClientOtherErrorRate":              ("客户端其他错误请求占比",        "%"),
    "SuccessCount":                      ("成功请求总数",                 "Count"),
    "SuccessRate":                       ("成功请求占比",                 "%"),
    "RedirectCount":                     ("重定向请求总数",               "Count"),
    "RedirectRate":                      ("重定向请求占比",               "%"),
    # 最大延时
    "MaxGetObjectE2eLatency":            ("GetObject最大E2E延时",         "ms"),
    "MaxGetObjectServerLatency":         ("GetObject最大服务器延时",       "ms"),
    "MaxHeadObjectE2eLatency":           ("HeadObject最大E2E延时",         "ms"),
    "MaxHeadObjectServerLatency":        ("HeadObject最大服务器延时",      "ms"),
    "MaxPostObjectE2eLatency":           ("PostObject最大E2E延时",         "ms"),
    "MaxPostObjectServerLatency":        ("PostObject最大服务器延时",      "ms"),
    "MaxPutObjectE2eLatency":            ("PutObject最大E2E延时",          "ms"),
    "MaxPutObjectServerLatency":         ("PutObject最大服务器延时",       "ms"),
    "MaxAppendObjectE2eLatency":         ("AppendObject最大E2E延时",       "ms"),
    "MaxAppendObjectServerLatency":      ("AppendObject最大服务器延时",    "ms"),
    "MaxUploadPartE2eLatency":           ("UploadPart最大E2E延时",         "ms"),
    "MaxUploadPartServerLatency":        ("UploadPart最大服务器延时",      "ms"),
    "MaxUploadPartCopyE2eLatency":       ("UploadPartCopy最大E2E延时",     "ms"),
    "MaxUploadPartCopyServerLatency":    ("UploadPartCopy最大服务器延时",  "ms"),
    # 成功请求操作分类
    "GetObjectCount":                    ("GetObject成功请求数",           "Count"),
    "HeadObjectCount":                   ("HeadObject成功请求数",          "Count"),
    "PutObjectCount":                    ("PutObject成功请求数",           "Count"),
    "PostObjectCount":                   ("PostObject成功请求数",          "Count"),
    "AppendObjectCount":                 ("AppendObject成功请求数",        "Count"),
    "UploadPartCount":                   ("UploadPart成功请求数",          "Count"),
    "UploadPartCopyCount":               ("UploadPartCopy成功请求数",      "Count"),
    "DeleteObjectCount":                 ("DeleteObject成功请求数",        "Count"),
    "DeleteObjectsCount":                ("DeleteObjects成功请求数",       "Count"),
}

OSS_NAMESPACE = "acs_oss_dashboard"

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
        "Namespace":  OSS_NAMESPACE,
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


# ── 主逻辑 ────────────────────────────────────────────────────────────────────

def main():
    dimensions = {"BucketName": OSS_BUCKET_NAME}
    result = {}

    for metric_name in OSS_METRICS:
        try:
            points = _get_metric_last(metric_name, dimensions)
            result[metric_name] = _extract_value(points[-1]) if points else None
        except Exception as e:
            result[metric_name] = f"ERROR: {e}"

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
