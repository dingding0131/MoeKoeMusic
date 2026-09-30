"""酷狗概念版(Lite)每日 VIP 领取协议核心。

协议细节对照公开参考实现 MakcRe/KuGouMusicApi 校验(提交 8f1cb0ea)。
本模块保持自包含:只依赖 requests / cryptography / 标准库,
UI 层(app.py)与协议层严格解耦,便于通过协议自更新机制整体替换。

不做验证码/风控绕过:服务端要求人工验证(ssa-code / 20028)时,
本核心会停止重试并把状态如实上报给 UI。
"""
from __future__ import annotations

PROTOCOL_VERSION = "2026.09.28.4"
UPSTREAM_REPO = "MakcRe/KuGouMusicApi"
UPSTREAM_COMMIT = "8f1cb0ea277db4f4ca106035dd41a871b9951e91"

import base64
import hashlib
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, asdict, fields as dc_fields
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from zoneinfo import ZoneInfo
    CN_TZ = ZoneInfo("Asia/Shanghai")
except Exception:  # Windows 上缺 tzdata 时的兜底;中国无夏令时,固定 +8 恒等价
    CN_TZ = timezone(timedelta(hours=8), "Asia/Shanghai")

LITE_APPID = 3116
LITE_CLIENTVER = 11440
SRC_APPID = 2919
ANDROID_SALT = "LnT6xpN3khm36zse0QzvmgTZ3waWdRSA"
WEB_SALT = "NVPh5oo715z5DIWAeQlhMDsWXXQV4hwt"

# 上游常量热修补:酷狗最常见的协议变化是 appid/clientver/盐值这类"常量"。
# 这些值可由 updater 匿名抓取上游公开文件后,经 apply_overrides 注入,
# 无需发布新核心即可自动跟上(端点 URL 不允许热修补,防止请求被重定向)。
_CONSTANT_RULES = {
    "android_salt": ("ANDROID_SALT", "salt"),
    "web_salt": ("WEB_SALT", "salt"),
    "lite_appid": ("LITE_APPID", "int"),
    "lite_clientver": ("LITE_CLIENTVER", "int"),
    "srcappid": ("SRC_APPID", "int"),
}


def apply_overrides(values: dict[str, Any]) -> list[str]:
    """把上游同步来的常量注入本模块(带严格校验,非法值整体拒绝)。

    返回实际生效的键列表。仅接受常量,不接受 URL/逻辑。
    """
    import re as _re
    applied: list[str] = []
    clean: dict[str, Any] = {}
    for key, value in (values or {}).items():
        rule = _CONSTANT_RULES.get(key)
        if not rule:
            continue
        name, kind = rule
        if kind == "salt":
            if isinstance(value, str) and _re.fullmatch(r"[0-9A-Za-z]{16,64}", value):
                clean[name] = value
        else:
            try:
                num = int(value)
            except (TypeError, ValueError):
                continue
            if 1 <= num <= 2_000_000_000:
                clean[name] = str(num)
    if not clean:
        return []
    for name, value in clean.items():
        globals()[name] = value
        applied.append(name)
    return applied


def current_constants() -> dict[str, Any]:
    """当前生效的协议常量(供同步层比对)。"""
    return {
        "android_salt": ANDROID_SALT,
        "web_salt": WEB_SALT,
        "lite_appid": LITE_APPID,
        "lite_clientver": LITE_CLIENTVER,
        "srcappid": SRC_APPID,
    }

PUBLIC_LITE_RSA = b"""-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDECi0Np2UR87scwrvTr72L6oO01rBbbBPriSDFPxr3Z5syug0O24QyQO8bg27+0+4kBzTBTBOZ/WWU0WryL1JSXRTXLgFVxtzIY41Pe7lPOgsfTCn5kZcvKhYKJesKnnJDNr5/abvTGf+rHG3YRwsCHcQ08/q6ifSioBszvb3QiwIDAQAB
-----END PUBLIC KEY-----"""

# login_by_pwd 的固定设备串(与上游 module/login.js 一致)
LOGIN_T1 = "562a6f12a6e803453647d16a08f5f0c2ff7eee692cba2ab74cc4c8ab47fc467561a7c6b586ce7dc46a63613b246737c03a1dc8f8d162d8ce1d2c71893d19f1d4b797685a4c6d3d81341cbde65e488c4829a9b4d42ef2df470eb102979fa5adcdd9b4eecfea8b909ff7599abeb49867640f10c3c70fc444effca9d15db44a9a6c907731e2bb0f22cd9b3536380169995693e5f0e2424e3378097d3813186e3fe96bbe7023808a0981b4e2b6135a76faac"
LOGIN_T2 = "31c4daf4cf480169ccea1cb7d4a209295865a9d2b788510301694db229b87807469ea0d41b4d4b9173c2151da7294aeebfc9738df154bbdf11a4e117bb5dff6a3af8ce5ce333e681c1f29a44038f27567d58992eb81283e080778ac77db1400fdf49b7cf7e26be2e5af4da7830cc3be4"
LOGIN_T3 = "MCwwLDAsMCwwLDAsMCwwLDA="

# login_by_token(概念版)密钥,与上游 module/login_token.js 一致
REFRESH_KEY = "c24f74ca2820225badc01946dba4fdf7"
REFRESH_IV = "adc01946dba4fdf7"
REFRESH_T2_KEY = "fd14b35e3f81af3817a20ae7adae7020"
REFRESH_T2_IV = "17a20ae7adae7020"
REFRESH_T1_KEY = "5e4ef500e9597fe004bd09a46d8add98"
REFRESH_T1_IV = "04bd09a46d8add98"

UA = "Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi"
UA_LISTEN = "Android13-1070-10566-201-0-ReportPlaySongToServerProtocol-wifi"
HEADERS_BASE = {
    "User-Agent": UA,
    "kg-rc": "1",
    "kg-thash": "5d816a0",
    "kg-rec": "1",
    "kg-rf": "B9EDA08A64250DEFFBCADDEE00F8F25F",
}

# 服务端业务错误码(与 MoeKoeMusic 客户端行为对齐)
ERR_ALREADY_RECEIVED = 131001   # 今天已经领取过
ERR_VERIFICATION = 20028        # 账号风控,需要人工在手机端处理
DEFAULT_LISTEN_MIXSONGID = 666075191  # 上游 youth_listen_song 默认上报歌曲

# 常见错误码的面向用户说明(服务端未带文字时使用)
ERROR_CODE_TEXT = {
    20006: "账号不存在或密码错误",
    20028: "账号风控,请到手机酷狗App完成一次操作后重试",
    131001: "今天已经领取过",
}


def md5(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.md5(value).hexdigest()


def rand_string(n: int) -> str:
    alphabet = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def aes_cbc_hex(plain: str | bytes, key: bytes, iv: bytes) -> bytes:
    if isinstance(plain, str):
        plain = plain.encode("utf-8")
    pad = 16 - (len(plain) % 16)
    plain += bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(plain) + enc.finalize()


def aes_cbc_decrypt(raw: bytes, key: bytes, iv: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plain = dec.update(raw) + dec.finalize()
    pad = plain[-1]
    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS7 padding")
    return plain[:-pad]


def crypto_aes_encrypt(data: Any, explicit_key: str | None = None, explicit_iv: str | None = None) -> tuple[str, str]:
    """与上游 cryptoAesEncrypt 一致:md5(temp) 十六进制串按 ASCII 字节作密钥。

    注意:CryptoJS 的 Utf8.parse 是把字符串按 ASCII/UTF-8 字节取值,
    不能对 md5 结果做十六进制解码,否则密钥长度与内容都错,服务端无法解密。
    """
    payload = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    if explicit_key is None:
        temp = rand_string(16).lower()
        key_hex = md5(temp)
        key = key_hex.encode("ascii")       # 32 字节 -> AES-256
        iv = key_hex[16:].encode("ascii")   # 16 字节
        return aes_cbc_hex(payload, key, iv).hex(), temp
    key = explicit_key.encode("utf-8")
    iv = (explicit_iv or explicit_key[-16:]).encode("utf-8")
    return aes_cbc_hex(payload, key, iv).hex(), explicit_key


def crypto_aes_decrypt_hex(data_hex: str, temp: str) -> bytes:
    """上游 cryptoAesDecrypt(data, temp) 的等价实现(secu_params 解密)。"""
    key_hex = md5(temp)
    return aes_cbc_decrypt(bytes.fromhex(data_hex), key_hex.encode("ascii"), key_hex[16:].encode("ascii"))


def raw_rsa_hex(data: Any) -> str:
    """裸 RSA(左侧零填充,无 padding 编码),对应上游 cryptoRSAEncrypt。"""
    payload = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    raw = payload.encode("utf-8")
    pub = serialization.load_pem_public_key(PUBLIC_LITE_RSA)
    nums = pub.public_numbers()
    size = (nums.n.bit_length() + 7) // 8
    if len(raw) > size:
        raise ValueError("RSA plaintext too long")
    raw = b"\x00" * (size - len(raw)) + raw
    value = pow(int.from_bytes(raw, "big"), nums.e, nums.n)
    return value.to_bytes(size, "big").hex()


def pkcs1_rsa_hex(data: Any) -> str:
    """RSAES-PKCS1-V1_5,对应上游 rsaEncrypt2(输出小写 hex)。"""
    payload = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    pub = serialization.load_pem_public_key(PUBLIC_LITE_RSA)
    return pub.encrypt(payload.encode("utf-8"), padding.PKCS1v15()).hex()


def playlist_aes_encrypt(data: Any) -> tuple[str, str]:
    """与上游 playlistAesEncrypt 一致:key/iv 为 md5(temp) 的 ASCII 字节段(AES-128)。"""
    temp = rand_string(6).lower()
    h = md5(temp)
    key = h[:16].encode("ascii")
    iv = h[16:].encode("ascii")
    payload = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    enc = aes_cbc_hex(payload, key, iv)
    return base64.b64encode(enc).decode("ascii"), temp


def playlist_aes_decrypt(raw: bytes, temp: str) -> dict:
    h = md5(temp)
    key = h[:16].encode("ascii")
    iv = h[16:].encode("ascii")
    txt = aes_cbc_decrypt(raw, key, iv).decode("utf-8")
    return json.loads(txt)


def web_signature(params: dict[str, Any], data: str = "") -> str:
    """与上游 signatureWebParams 逐字一致:先拼 k=v 再对整串排序。"""
    params_string = "".join(sorted(f"{k}={params[k]}" for k in params))
    return md5(f"{WEB_SALT}{params_string}{data}{WEB_SALT}")


def android_signature(params: dict[str, Any], data: str = "") -> str:
    """与上游 signatureAndroidParams 一致:按 key 排序拼 k=v,对象值转 JSON。"""
    parts = []
    for key in sorted(params):
        value = params[key]
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        parts.append(f"{key}={value}")
    return md5(f"{ANDROID_SALT}{''.join(parts)}{data}{ANDROID_SALT}")


def calculate_mid(guid_md5: str) -> str:
    return str(int(guid_md5, 16))


def make_device() -> dict[str, str]:
    raw_guid = str(uuid.uuid4()).lower()
    guid = md5(raw_guid)
    return {
        "guid": guid,
        "mid": calculate_mid(guid),
        "dev": rand_string(10).upper(),
        "mac": "02:00:00:00:00:00",
        "webgl": str(secrets.randbits(64)),
        "dfid": "-",
    }


@dataclass
class Account:
    id: str
    username: str
    nickname: str = ""
    userid: str = ""
    token: str = ""
    t1: str = ""
    vip_type: str = "0"
    vip_token: str = ""
    last_sign_date: str = ""
    last_sign_message: str = ""
    last_vip_date: str = ""
    last_vip_message: str = ""
    enabled: bool = True
    device: dict[str, str] | None = None

    @staticmethod
    def from_stored(data: dict[str, Any]) -> "Account":
        """容错反序列化:忽略未知字段,补齐缺失字段,迁移旧字段,修复不完整的设备指纹。"""
        known = {f.name for f in dc_fields(Account)}
        legacy_map = {"last_checkin_date": "last_vip_date", "last_checkin_message": "last_vip_message"}
        account = Account(id="dummy", username="")
        for key, value in data.items():
            if key in known:
                setattr(account, key, value)
            elif key in legacy_map:
                setattr(account, legacy_map[key], value)
        if not account.id or account.id == "dummy":
            account.id = str(uuid.uuid4())
        device_keys = {"guid", "mid", "dev", "mac", "webgl", "dfid"}
        if not isinstance(account.device, dict) or not device_keys.issubset(account.device):
            account.device = make_device()
        return account

    @staticmethod
    def new(username: str) -> "Account":
        return Account(id=str(uuid.uuid4()), username=username, device=make_device())


class KugouError(RuntimeError):
    def __init__(self, message: str, code: int | None = None, verification: bool = False):
        super().__init__(message)
        self.code = code
        self.verification = verification


class KugouClient:
    def __init__(self, account: Account, logger: logging.Logger | None = None):
        self.account = account
        self.logger = logger or logging.getLogger("KugouDailyCheckin")
        self.session = requests.Session()
        self.session.headers.update(HEADERS_BASE)
        if not isinstance(account.device, dict):
            account.device = make_device()
        self.device = account.device

    # ---------- 基础请求 ----------

    def _base_params(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        now = int(time.time())
        p: dict[str, Any] = {
            "dfid": self.device.get("dfid", "-"),
            "mid": self.device["mid"],
            "uuid": "-",
            "appid": LITE_APPID,
            "clientver": LITE_CLIENTVER,
            "clienttime": now,
        }
        if self.account.token:
            p["token"] = self.account.token
        if self.account.userid:
            p["userid"] = self.account.userid
        if extra:
            p.update(extra)
        return p

    def _request(self, method: str, url: str, extra_params: dict[str, Any] | None = None,
                 body: Any | None = None, encrypt: str = "android", headers: dict[str, str] | None = None,
                 timeout: int = 20, raw: bool = False, retries: int = 0) -> tuple[requests.Response, Any]:
        data = ""
        wire_body = None
        if body is not None:
            if isinstance(body, str):
                data = body
                wire_body = body
            elif isinstance(body, (bytes, bytearray)):
                data = bytes(body).decode("latin1")
                wire_body = bytes(body)
            else:
                data = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
                wire_body = data
        params = self._base_params(extra_params)
        params["signature"] = web_signature(params, data) if encrypt == "web" else android_signature(params, data)
        h = dict(headers or {})
        h.setdefault("dfid", self.device.get("dfid", "-"))
        h.setdefault("clienttime", str(params["clienttime"]))
        h.setdefault("mid", self.device["mid"])
        if method.upper() == "POST" and not isinstance(body, str):
            h.setdefault("Content-Type", "application/json")
        if method.upper() == "POST" and isinstance(body, str):
            h.setdefault("Content-Type", "application/octet-stream")
        attempts = max(0, int(retries)) + 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                resp = self.session.request(method, url, params=params, data=wire_body, headers=h,
                                            timeout=timeout)
                break
            except requests.RequestException as exc:
                last_exc = exc
                if attempt + 1 < attempts:
                    time.sleep(1.0)
        else:
            raise KugouError(f"网络请求失败：{last_exc}") from last_exc
        if raw:
            return resp, resp.content
        try:
            payload = resp.json()
        except ValueError:
            payload = {"status": 0, "msg": resp.text[:500]}
        if not isinstance(payload, dict):
            payload = {"status": 0, "msg": str(payload)[:500]}
        code = payload.get("error_code")
        status = payload.get("status")
        failed = resp.status_code >= 400 or status == 0 or (isinstance(code, int) and code != 0)
        if failed:
            text = payload.get("error_msg") or payload.get("errmsg") or payload.get("msg") or ""
            code_int = code if isinstance(code, int) else None
            if not text and code_int is not None:
                text = ERROR_CODE_TEXT.get(code_int, f"错误码 {code_int}")
            if not text:
                text = f"HTTP {resp.status_code}"
            ssa = resp.headers.get("ssa-code") or resp.headers.get("SSA-CODE")
            verification = (
                ssa is not None
                or code == ERR_VERIFICATION
                or "验证" in str(text)
                or "captcha" in str(text).lower()
            )
            raise KugouError(f"酷狗返回失败：{text}", code=code_int, verification=verification)
        return resp, payload

    # ---------- 设备 / 登录 ----------

    def register_device(self) -> None:
        body, temp = playlist_aes_encrypt({
            "availableRamSize": 4983533568,
            "availableRomSize": 48114719,
            "availableSDSize": 48114717,
            "basebandVer": "",
            "batteryLevel": 100,
            "batteryStatus": 3,
            "brand": "Xiaomi",
            "buildSerial": "unknown",
            "device": "marble",
            "imei": self.device["guid"],
            "imsi": "",
            "manufacturer": "Xiaomi",
            "uuid": self.device["guid"],
            "accelerometer": False,
            "accelerometerValue": "",
            "gravity": False,
            "gravityValue": "",
            "gyroscope": False,
            "gyroscopeValue": "",
            "light": False,
            "lightValue": "",
            "magnetic": False,
            "magneticValue": "",
            "orientation": False,
            "orientationValue": "",
            "pressure": False,
            "pressureValue": "",
            "step_counter": False,
            "step_counterValue": "",
            "temperature": False,
            "temperatureValue": "",
        })
        p = pkcs1_rsa_hex({"aes": temp, "uid": self.account.userid or 0, "token": self.account.token})
        params = {"part": 1, "platid": 1, "p": p}
        try:
            resp, raw = self._request("POST", "https://userservice.kugou.com/risk/v2/r_register_dev", params,
                                      body=body, headers={"Content-Type": "application/octet-stream"}, raw=True)
            payload = playlist_aes_decrypt(raw, temp)
        except KugouError:
            raise
        except Exception as exc:
            raise KugouError(f"设备注册失败：{exc}") from exc
        if payload.get("status") != 1:
            raise KugouError(f"设备注册失败：{payload.get('error_msg') or payload.get('msg') or payload}")
        new_dfid = payload.get("data", {}).get("dfid") if isinstance(payload.get("data"), dict) else None
        if new_dfid:
            self.device["dfid"] = str(new_dfid)

    def password_login(self, username: str, password: str) -> None:
        now = int(time.time() * 1000)
        encrypted, temp = crypto_aes_encrypt({"pwd": password, "code": "", "clienttime_ms": now})
        body = {
            "plat": 1,
            "support_multi": 1,
            "clienttime_ms": now,
            "t1": LOGIN_T1,
            "t2": LOGIN_T2,
            "t3": LOGIN_T3,
            "dev": self.device["dev"],
            "username": username,
            "params": encrypted,
            "pk": raw_rsa_hex({"clienttime_ms": now, "key": temp}).upper(),
        }
        try:
            _, payload = self._request("POST", "https://gateway.kugou.com/v9/login_by_pwd", body=body,
                                       headers={"x-router": "login.user.kugou.com", "Content-Type": "application/json"})
        except KugouError:
            raise
        if payload.get("status") != 1:
            raise KugouError(payload.get("error_msg") or payload.get("errmsg") or payload.get("msg") or "登录失败",
                             payload.get("error_code") if isinstance(payload.get("error_code"), int) else None,
                             verification=payload.get("error_code") == ERR_VERIFICATION)
        data = payload.get("data") or {}
        if data.get("secu_params"):
            try:
                dec = crypto_aes_decrypt_hex(data["secu_params"], temp).decode("utf-8")
                token_data = json.loads(dec) if dec.startswith("{") else {"token": dec}
                data.update(token_data)
            except Exception as exc:
                raise KugouError(f"登录响应解密失败：{exc}") from exc
        self._apply_login(data, username)

    def qr_key(self) -> tuple[str, str]:
        params = {
            "appid": 1001,
            "type": 1,
            "plat": 4,
            "qrcode_txt": f"https://h5.kugou.com/apps/loginQRCode/html/index.html?appid={LITE_APPID}&",
            "srcappid": SRC_APPID,
        }
        _, payload = self._request("GET", "https://login-user.kugou.com/v2/qrcode", params, encrypt="web")
        data = payload.get("data") or {}
        key = data.get("qrcode") or data.get("key") or payload.get("qrcode")
        if not key:
            raise KugouError(f"二维码 Key 获取失败：{payload}")
        url = f"https://h5.kugou.com/apps/loginQRCode/html/index.html?qrcode={key}"
        return str(key), url

    def qr_check(self, key: str) -> dict[str, Any]:
        params = {
            "plat": 4,
            "appid": LITE_APPID,
            "srcappid": SRC_APPID,
            "qrcode": key,
            "dev": self.device["dev"],
            "timestamp": int(time.time() * 1000),
        }
        _, payload = self._request("GET", "https://login-user.kugou.com/v2/get_userinfo_qrcode", params, encrypt="web")
        data = payload.get("data") or {}
        return {"status": data.get("status"), **data}

    def _apply_login(self, data: dict[str, Any], username: str) -> None:
        token = data.get("token")
        userid = data.get("userid")
        if not token or not userid:
            raise KugouError(f"登录成功但没有取得 token/userid：{data}")
        self.account.username = username
        self.account.token = str(token)
        self.account.userid = str(userid)
        self.account.nickname = str(data.get("nickname") or data.get("username") or username)
        self.account.t1 = str(data.get("t1") or self.account.t1)
        self.account.vip_type = str(data.get("vip_type") or self.account.vip_type)
        self.account.vip_token = str(data.get("vip_token") or self.account.vip_token)

    def refresh_token(self) -> None:
        if not self.account.token or not self.account.userid:
            raise KugouError("没有可刷新登录态")
        now = int(time.time() * 1000)
        encrypted, _ = crypto_aes_encrypt({"clienttime": now // 1000, "token": self.account.token},
                                          REFRESH_KEY, REFRESH_IV)
        empty_hex, temp = crypto_aes_encrypt({})
        t2_hex, _ = crypto_aes_encrypt(
            f"{self.device['guid']}|0f607264fc6318a92b9e13c65db7cd3c|{self.device['mac']}|{self.device['dev']}|{now}",
            REFRESH_T2_KEY, REFRESH_T2_IV)
        t1_hex, _ = crypto_aes_encrypt(f"{self.account.t1 + '|' if self.account.t1 else '|'}{now}",
                                       REFRESH_T1_KEY, REFRESH_T1_IV)
        body = {
            "dfid": self.device.get("dfid", "-"),
            "p3": encrypted,
            "plat": 1,
            "t1": t1_hex,
            "t2": t2_hex,
            "t3": LOGIN_T3,
            "pk": raw_rsa_hex({"clienttime_ms": now, "key": temp}),
            "params": empty_hex,
            "userid": self.account.userid,
            "clienttime_ms": now,
            "dev": self.device["dev"],
        }
        params = self._base_params()
        data_string = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        params["signature"] = android_signature(params, data_string)
        h = dict(HEADERS_BASE)
        h.update({"dfid": self.device.get("dfid", "-"), "clienttime": str(params["clienttime"]),
                  "mid": self.device["mid"], "Content-Type": "application/json"})
        last_exc: Exception | None = None
        # 上游直接走 http;https 证书可能不覆盖该主机名,故 https 优先、http 兜底。
        for base in ("https://login.user.kugou.com", "http://login.user.kugou.com"):
            try:
                r = self.session.post(base + "/v5/login_by_token", params=params, json=body, headers=h, timeout=20)
            except requests.RequestException as exc:
                last_exc = exc
                continue
            try:
                payload = r.json()
            except ValueError:
                payload = {"status": 0, "msg": r.text[:300]}
            if r.status_code < 400 and payload.get("status") == 1:
                data = payload.get("data") or {}
                if data.get("secu_params"):
                    try:
                        dec = crypto_aes_decrypt_hex(data["secu_params"], temp).decode("utf-8")
                        data.update(json.loads(dec) if dec.startswith("{") else {"token": dec})
                    except Exception as exc:
                        raise KugouError(f"刷新响应解密失败：{exc}") from exc
                self._apply_login(data, self.account.username)
                return
            code = payload.get("error_code")
            last_exc = KugouError(payload.get("error_msg") or payload.get("msg") or f"刷新失败 {r.status_code}",
                                  code if isinstance(code, int) else None,
                                  verification=code == ERR_VERIFICATION)
        raise KugouError(f"登录态刷新失败：{last_exc}")

    # ---------- 业务查询 / 领取 ----------

    def daily_record(self) -> dict[str, Any]:
        _, payload = self._request("GET", "https://gateway.kugou.com/youth/v1/activity/get_month_vip_record",
                                   {"latest_limit": 100}, retries=1)
        return payload

    def claim_today(self, date_text: str) -> dict[str, Any]:
        _, payload = self._request("POST", "https://gateway.kugou.com/youth/v1/recharge/receive_vip_listen_song",
                                   {"source_id": 90139, "receive_day": date_text}, body="",
                                   headers={"Content-Type": "application/x-www-form-urlencoded"})
        return payload

    def claim_upgrade(self) -> dict[str, Any]:
        """领取后升级概念版 VIP(MoeKoeMusic 客户端在领取成功后调用)。"""
        kugouid = int(self.account.userid) if str(self.account.userid).isdigit() else 0
        _, payload = self._request("POST", "https://gateway.kugou.com/youth/v1/listen_song/upgrade_vip_reward",
                                   {"kugouid": kugouid, "ad_type": 1}, body="")
        return payload

    def report_listen_song(self) -> None:
        """听歌上报(上游 youth_listen_song 的默认歌曲)。领取前的活动前置条件,尽力而为。"""
        self._request("POST", "https://gateway.kugou.com/youth/v2/report/listen_song",
                      {"clientver": 10566}, body={"mixsongid": DEFAULT_LISTEN_MIXSONGID},
                      headers={"User-Agent": UA_LISTEN, "Content-Type": "application/json; charset=utf-8"})

    def vip_status(self) -> dict[str, Any]:
        _, payload = self._request("GET", "https://kugouvip.kugou.com/v1/get_union_vip",
                                   {"busi_type": "concept", "opt_product_types": "dvip,qvip",
                                    "product_type": "svip"}, retries=1)
        return payload

    def daily_sign(self) -> dict[str, Any]:
        """每日“签到”(看广告领VIP时长):/youth/v1/ad/play_report。

        与上游 youth_vip.js 一致:上报一次 30 秒广告播放,官方每次奖励
        3 小时 VIP(每天最多 8 次)。是否可用由服务端决定,结果如实上报。
        """
        now_ms = int(time.time() * 1000)
        _, payload = self._request("POST", "https://gateway.kugou.com/youth/v1/ad/play_report",
                                   body={"ad_id": 12307537187, "play_end": now_ms,
                                         "play_start": now_ms - 30000})
        return payload

    def already_received(self, record: dict[str, Any], date_text: str) -> bool:
        """在当月领取记录中寻找“该日期 + 成功标记”同时出现的证据。"""

        def walk(x: Any) -> bool:
            if isinstance(x, dict):
                date_found = any(str(v) == date_text for v in x.values())
                positive = any(str(v).lower() in {"1", "true", "success", "received", "receive"} for v in x.values())
                if date_found and positive:
                    return True
                return any(walk(v) for v in x.values())
            if isinstance(x, list):
                return any(walk(v) for v in x)
            return False

        return walk(record)

    # ---------- 每日任务主流程 ----------

    def _ensure_session(self) -> None:
        """公共前置:设备注册(仅缺失时)、刷新登录态、登录态校验(失败重试一次)。"""
        if not self.device.get("dfid") or self.device["dfid"] == "-":
            self.register_device()
        try:
            self.refresh_token()
        except KugouError as exc:
            if exc.verification:
                raise
            self.logger.info("token 刷新未成功,使用现有登录态继续：%s", exc)
        try:
            self.vip_status()
        except KugouError as exc:
            if exc.verification:
                raise
            self.logger.info("登录态校验失败,重建设备后重试：%s", exc)
            self.register_device()
            self.refresh_token()
            self.vip_status()

    @staticmethod
    def _verification_text(code: int | None) -> str:
        return (f"需要人工验证（错误码 {code or '-'}），"
                "请稍后在手机酷狗App完成一次操作后重试；本程序不会自动绕过验证")

    def sign_daily(self) -> tuple[bool, str]:
        """任务一:每日签到(广告上报,官方奖励 3 小时 VIP/次)。结果如实上报。"""
        today = datetime.now(CN_TZ).strftime("%Y-%m-%d")
        if self.account.last_sign_date == today:
            return True, self.account.last_sign_message or "今天已签到"
        try:
            payload = self.daily_sign()
            data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            hours = data.get("award_vip_hour") or data.get("award_vip") or data.get("award") or ""
            msg = "签到成功" + (f"（+{hours}小时VIP）" if str(hours) not in ("", "0") else "")
        except KugouError as exc:
            if exc.verification:
                return False, self._verification_text(exc.code)
            return False, str(exc)
        except Exception as exc:
            return False, f"签到异常：{exc}"
        self.account.last_sign_date = today
        self.account.last_sign_message = msg
        return True, msg

    def vip_daily(self, try_upgrade: bool = True) -> tuple[bool, str]:
        """任务二:听歌领一天 VIP(+可选升级概念版)。结果如实上报。"""
        today = datetime.now(CN_TZ).strftime("%Y-%m-%d")
        try:
            if self.account.last_vip_date == today:
                return True, self.account.last_vip_message or "今天已领取"

            # 当月记录预检,避免重复领取。
            try:
                record = self.daily_record()
                if self.already_received(record, today):
                    self.account.last_vip_date = today
                    self.account.last_vip_message = "今天已经领取"
                    return True, "今天已经领取"
            except KugouError as exc:
                if exc.verification:
                    raise
                self.logger.warning("读取领取记录失败,继续一次领取尝试：%s", exc)

            # 听歌上报(活动前置条件,尽力而为,失败不阻断)。
            try:
                self.report_listen_song()
            except KugouError as exc:
                self.logger.info("听歌上报未成功(不阻断领取)：%s", exc)

            # 领取。131001 = 今天已领,视为成功。
            try:
                result = self.claim_today(today)
                msg = "领取成功"
                if isinstance(result, dict):
                    msg = str(result.get("msg") or result.get("error_msg")
                              or (result.get("data") or {}).get("msg") or msg)
            except KugouError as exc:
                if exc.code == ERR_ALREADY_RECEIVED:
                    self.account.last_vip_date = today
                    self.account.last_vip_message = "今天已经领取"
                    return True, "今天已经领取"
                raise

            self.account.last_vip_date = today
            self.account.last_vip_message = str(msg)
            detail = str(msg)

            # 升级概念版(尽力而为,一天一次,失败不影响已领结果)。
            if try_upgrade:
                try:
                    self.claim_upgrade()
                    detail += "；已尝试升级概念版VIP"
                except KugouError as exc:
                    self.logger.info("概念版升级未成功(不影响领取)：%s", exc)

            # 复核当月记录。
            try:
                record2 = self.daily_record()
                if self.already_received(record2, today):
                    return True, detail + "；已在当月领取记录确认"
            except KugouError:
                pass
            return True, detail
        except KugouError as exc:
            if exc.verification:
                return False, self._verification_text(exc.code)
            return False, str(exc)
        except Exception as exc:
            return False, f"领取异常：{exc}"

    def run_daily_tasks(self, try_upgrade: bool = True) -> list[tuple[str, bool, str]]:
        """每日全部任务:签到 + VIP领取。返回 [("签到", ok, msg), ("VIP", ok, msg)]。"""
        results: list[tuple[str, bool, str]] = []
        try:
            self._ensure_session()
        except KugouError as exc:
            msg = self._verification_text(exc.code) if exc.verification else str(exc)
            return [("签到", False, msg), ("VIP", False, msg)]
        except Exception as exc:
            msg = f"登录态准备失败:{exc}"
            return [("签到", False, msg), ("VIP", False, msg)]
        results.append(("签到",) + self.sign_daily())
        results.append(("VIP",) + self.vip_daily(try_upgrade))
        return results

    def checkin(self, try_upgrade: bool = True) -> tuple[bool, str]:
        """兼容旧版调用(1.1.0 程序 + 新核心):仅执行 VIP 领取任务。"""
        return self.vip_daily(try_upgrade)


__all__ = ["PROTOCOL_VERSION", "UPSTREAM_REPO", "UPSTREAM_COMMIT", "Account", "KugouClient",
           "KugouError", "make_device", "asdict",
           "ERR_ALREADY_RECEIVED", "ERR_VERIFICATION"]
