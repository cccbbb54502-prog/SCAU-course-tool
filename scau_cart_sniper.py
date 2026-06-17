#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlencode, urljoin

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text


BASE_URL = "https://jwzf.scau.edu.cn"
GNMKDM = "N253512"
LOGIN_PATH = "/jwglxt/xtgl/login_slogin.html"
COURSE_INDEX_PATH = "/jwglxt/xsxk/zzxkyzb_cxZzxkYzbIndex.html"
CART_PATH = "/jwglxt/xsxk/zzxkyzb_cxWdgwcZzxkYzb.html"
SUBMIT_PATH = "/jwglxt/xsxk/zzxkyzbjk_xkBcZyZzxkYzbFromCart.html"

DEFAULT_CONFIG: dict[str, Any] = {
    "duration_seconds": 600,
    "speed_profile": "medium",
    "speed_profiles": {
        "ultra_fast": 0.01,
        "fast": 0.1,
        "medium": 0.2,
        "slow": 0.5,
    },
}

SUCCESS_KEYWORDS = (
    "成功",
    "选课成功",
    "保存成功",
)
FULL_KEYWORDS = (
    "满课",
    "已满",
    "容量",
    "名额",
    "人数已满",
    "余量不足",
    "无余量",
    "没有余量",
    "超过课容量",
    "超过选课人数",
)
RETRY_KEYWORDS = (
    "未开始",
    "不在选课时间",
    "选课时间未到",
    "暂未开始",
    "系统繁忙",
    "稍后",
    "重试",
    "网络",
    "超时",
    "timeout",
    "temporarily",
)
STOP_KEYWORDS = (
    "冲突",
    "时间冲突",
    "已选",
    "已经选",
    "重复",
    "不符合",
    "限制",
    "培养方案",
    "不可选",
    "不能选",
    "不允许",
    "先修",
    "学分",
    "性别",
    "年级",
    "专业",
)


class SniperError(RuntimeError):
    """Expected runtime error that can be shown safely."""


@dataclass
class Config:
    duration_seconds: int
    speed_profile: str
    speed_profiles: dict[str, float]

    @property
    def interval_seconds(self) -> float:
        if self.speed_profile not in self.speed_profiles:
            known = ", ".join(sorted(self.speed_profiles))
            raise SniperError(f"未知速度档位: {self.speed_profile}。可选: {known}")
        value = float(self.speed_profiles[self.speed_profile])
        if value < 0:
            raise SniperError("速度间隔不能为负数。")
        return value


@dataclass
class CartCourse:
    index: int
    raw: dict[str, Any]
    cart_id: str
    name: str
    class_name: str
    course_type: str
    joined_at: str
    year: str
    term: str
    status: str = "等待"
    detail: str = ""
    attempts: int = 0
    last_message: str = ""
    active: bool = True
    success: bool = False


@dataclass
class SubmitResult:
    category: str
    message: str
    raw: Any = field(repr=False, default=None)


def now_ms() -> int:
    return int(time.time() * 1000)


def load_config(path: Path) -> Config:
    data = json.loads(json.dumps(DEFAULT_CONFIG))
    if path.exists():
        with path.open("r", encoding="utf-8") as fp:
            user_config = json.load(fp)
        if not isinstance(user_config, dict):
            raise SniperError("配置文件必须是 JSON 对象。")
        for key, value in user_config.items():
            if key == "speed_profiles" and isinstance(value, dict):
                data["speed_profiles"].update(value)
            else:
                data[key] = value
    return Config(
        duration_seconds=int(data["duration_seconds"]),
        speed_profile=str(data["speed_profile"]),
        speed_profiles={k: float(v) for k, v in data["speed_profiles"].items()},
    )


def b64decode_lenient(value: str) -> bytes:
    cleaned = value.strip()
    padding = "=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned + padding)


def encrypt_password(plain_password: str, modulus_b64: str, exponent_b64: str) -> str:
    modulus = int.from_bytes(b64decode_lenient(modulus_b64), "big")
    exponent = int.from_bytes(b64decode_lenient(exponent_b64), "big")
    public_key = RSA.construct((modulus, exponent))
    cipher = PKCS1_v1_5.new(public_key)
    encrypted = cipher.encrypt(plain_password.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


def encrypt_password_jsbn_style(plain_password: str, modulus_b64: str, exponent_b64: str) -> str:
    modulus = int(b64tohex(modulus_b64), 16)
    exponent = int(b64tohex(exponent_b64), 16)
    key_bytes = (modulus.bit_length() + 7) // 8
    padded = pkcs1pad2_jsbn(plain_password, key_bytes)
    encrypted_int = pow(padded, exponent, modulus)
    encrypted_hex = format(encrypted_int, "x")
    if len(encrypted_hex) % 2:
        encrypted_hex = "0" + encrypted_hex
    return hex2b64_jsbn(encrypted_hex)


def pkcs1pad2_jsbn(text: str, key_bytes: int) -> int:
    encoded = text.encode("utf-8")
    if key_bytes < len(encoded) + 11:
        raise SniperError("密码过长，无法按 RSA PKCS#1 v1.5 加密。")
    padding_len = key_bytes - len(encoded) - 3
    padding = bytearray()
    while len(padding) < padding_len:
        byte = os.urandom(1)[0]
        if byte:
            padding.append(byte)
    block = b"\x00\x02" + bytes(padding) + b"\x00" + encoded
    return int.from_bytes(block, "big")


def b64tohex(value: str) -> str:
    b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    ret = ""
    state = 0
    slop = 0
    for ch in value:
        if ch == "=":
            break
        v = b64map.find(ch)
        if v < 0:
            continue
        if state == 0:
            ret += format(v >> 2, "x")
            slop = v & 3
            state = 1
        elif state == 1:
            ret += format((slop << 2) | (v >> 4), "x")
            slop = v & 0xF
            state = 2
        elif state == 2:
            ret += format(slop, "x")
            ret += format(v >> 2, "x")
            slop = v & 3
            state = 3
        else:
            ret += format((slop << 2) | (v >> 4), "x")
            ret += format(v & 0xF, "x")
            state = 0
    if state == 1:
        ret += format(slop << 2, "x")
    return ret


def hex2b64_jsbn(hex_value: str) -> str:
    b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    ret = ""
    i = 0
    while i + 3 <= len(hex_value):
        c = int(hex_value[i:i + 3], 16)
        ret += b64map[c >> 6] + b64map[c & 63]
        i += 3
    if i + 1 == len(hex_value):
        c = int(hex_value[i:i + 1], 16)
        ret += b64map[c << 2]
    elif i + 2 == len(hex_value):
        c = int(hex_value[i:i + 2], 16)
        ret += b64map[c >> 2] + b64map[(c & 3) << 4]
    while len(ret) & 3:
        ret += "="
    return ret


def parse_hidden_inputs(html: str) -> dict[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    values: dict[str, str] = {}
    for node in soup.find_all("input"):
        name = node.get("name") or node.get("id")
        if not name:
            continue
        values[name] = node.get("value", "")
    return values


def contains_any(text: str, keywords: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(keyword.lower() in lowered for keyword in keywords)


def classify_submit_response(response: Any, http_status: int = 200) -> SubmitResult:
    if http_status in (401, 403):
        return SubmitResult("auth_expired", f"登录态可能已失效，HTTP {http_status}", response)
    if http_status >= 500:
        return SubmitResult("retry", f"服务器暂时异常，HTTP {http_status}", response)
    if http_status >= 400:
        return SubmitResult("stop", f"请求失败，HTTP {http_status}", response)

    item = response[0] if isinstance(response, list) and response else response
    if not isinstance(item, dict):
        return SubmitResult("retry", "响应格式暂时无法识别", response)

    flag = str(item.get("flag", "")).strip()
    msg = str(item.get("msg", "")).strip() or "无返回消息"
    if flag in {"1", "true", "True", "success", "SUCCESS"} or contains_any(msg, SUCCESS_KEYWORDS):
        return SubmitResult("success", msg, response)
    if contains_any(msg, FULL_KEYWORDS):
        return SubmitResult("full", msg, response)
    if contains_any(msg, RETRY_KEYWORDS):
        return SubmitResult("retry", msg, response)
    if contains_any(msg, STOP_KEYWORDS):
        return SubmitResult("stop", msg, response)
    if flag == "0":
        return SubmitResult("stop", msg, response)
    return SubmitResult("retry", msg, response)


def course_sort_key(item: dict[str, Any]) -> tuple[str, int]:
    joined = str(item.get("zjsj") or "")
    row_id = item.get("row_id", 0)
    try:
        row = int(row_id)
    except (TypeError, ValueError):
        row = 0
    return joined, row


def parse_cart_courses(payload: dict[str, Any]) -> list[CartCourse]:
    items = payload.get("items", [])
    if not isinstance(items, list):
        raise SniperError("购物车响应中没有可用的 items 列表。")

    courses: list[CartCourse] = []
    for idx, item in enumerate(sorted(items, key=course_sort_key), start=1):
        if not isinstance(item, dict):
            continue
        cart_id = str(item.get("xkgwcb_id") or "").strip()
        if not cart_id:
            continue
        courses.append(
            CartCourse(
                index=idx,
                raw=item,
                cart_id=cart_id,
                name=str(item.get("kcmc") or "未知课程"),
                class_name=str(item.get("jxbmc") or item.get("zjxbmcs") or "未知教学班"),
                course_type=str(item.get("kklxmc") or "未知类型"),
                joined_at=str(item.get("zjsj") or "-"),
                year=str(item.get("xnm") or "-"),
                term=str(item.get("xqm") or "-"),
            )
        )
    return courses


def safe_course_line(course: CartCourse) -> str:
    return (
        f"#{course.index} {course.name} | {course.class_name} | "
        f"{course.course_type} | 加入时间 {course.joined_at}"
    )


class ScauClient:
    def __init__(self, base_url: str = BASE_URL, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.course_context: dict[str, str] = {}
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0 Safari/537.36"
                ),
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )

    def url(self, path: str) -> str:
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def ajax_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.base_url,
            "Referer": self.url(
                f"{COURSE_INDEX_PATH}?gnmkdm={GNMKDM}&layout=default"
            ),
        }

    def login_ajax_headers(self, referer: str) -> dict[str, str]:
        return {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.base_url,
            "Referer": referer,
        }

    def form_headers(self, referer: str) -> dict[str, str]:
        return {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.base_url,
            "Pragma": "no-cache",
            "Referer": referer,
            "Upgrade-Insecure-Requests": "1",
        }

    def document_headers(self, referer: str = "") -> dict[str, str]:
        headers = {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": "1",
        }
        if referer:
            headers["Referer"] = referer
        return headers

    def login(self, username: str, password: str) -> None:
        login_url = self.url(LOGIN_PATH)
        page = self.session.get(login_url, headers=self.document_headers(), timeout=self.timeout)
        page.raise_for_status()
        hidden = parse_hidden_inputs(page.text)
        csrf = hidden.get("csrftoken")
        if not csrf:
            raise SniperError("登录页未找到 csrftoken，可能页面结构已变化。")
        login_action_url = self.url(f"{LOGIN_PATH}?time={now_ms()}")

        ts = now_ms()
        public_key_url = self.url(
            f"/jwglxt/xtgl/login_getPublicKey.html?time={ts + random.randint(1, 999)}&_={ts}"
        )
        key_resp = self.session.get(
            public_key_url,
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": login_url,
            },
            timeout=self.timeout,
        )
        key_resp.raise_for_status()
        key_json = key_resp.json()
        modulus = key_json.get("modulus")
        exponent = key_json.get("exponent")
        if not modulus or not exponent:
            raise SniperError("公钥接口未返回 modulus/exponent。")

        mmsfjm = str(hidden.get("mmsfjm", "1"))
        encrypted_password = (
            password if mmsfjm == "0" else encrypt_password_jsbn_style(password, modulus, exponent)
        )

        login_ajax_headers = self.login_ajax_headers(login_url)

        xxqr_resp = self.session.post(
            self.url("/jwglxt/xtgl/yhgl_cxXxqrCheck.html"),
            headers=login_ajax_headers,
            data={"yhm": username},
            timeout=self.timeout,
        )
        try:
            if xxqr_resp.json() is True:
                raise SniperError("账号触发身份信息确认，当前脚本暂不支持该登录分支。")
        except ValueError:
            pass

        dlxgxx_resp = self.session.post(
            self.url("/jwglxt/xtgl/login_cxDlxgxx.html"),
            headers=login_ajax_headers,
            data={"yhm": username},
            timeout=self.timeout,
        )
        self._check_login_failure_counter(dlxgxx_resp, hidden, username, login_ajax_headers)
        self.session.post(
            self.url("/jwglxt/xtgl/login_logoutAccount.html"),
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": self.base_url,
                "Referer": login_url,
            },
            timeout=self.timeout,
        )

        login_data = [
            ("csrftoken", csrf),
            ("language", hidden.get("language", "zh_CN") or "zh_CN"),
            ("ydType", hidden.get("ydType", "")),
            ("yhm", username),
            ("mm", encrypted_password),
            ("mm", encrypted_password),
        ]
        login_resp = self.session.post(
            login_action_url,
            headers=self.form_headers(login_url),
            data=login_data,
            allow_redirects=False,
            timeout=self.timeout,
        )

        if login_resp.status_code in (301, 302, 303, 307, 308):
            if self._follow_login_redirects(login_resp, login_url):
                return

        location = login_resp.headers.get("Location", "")
        if login_resp.status_code in (301, 302, 303, 307, 308) and "index_initMenu" in location:
            target = self.url(location)
            follow = self.session.get(target, headers=self.document_headers(login_url), timeout=self.timeout)
            follow.raise_for_status()
            return

        if login_resp.status_code == 200:
            if self._looks_like_home_page(login_resp):
                return
            meta_refresh = self._extract_meta_refresh_url(login_resp.text)
            if meta_refresh and "index_initMenu" in meta_refresh:
                follow = self.session.get(self.url(meta_refresh), timeout=self.timeout)
                follow.raise_for_status()
                return

        safe_hint = self._safe_login_failure_hint(login_resp)
        raise SniperError(
            "登录失败：未收到学生首页跳转，请检查账号密码、短信验证或页面结构。或可提交issue反馈"
            f" 安全诊断: {safe_hint}"
        )

    def open_course_index(self) -> None:
        resp = self.session.get(
            self.url(f"{COURSE_INDEX_PATH}?gnmkdm={GNMKDM}&layout=default"),
            headers={"Referer": self.url("/jwglxt/xtgl/index_initMenu.html?jsdm=xs")},
            timeout=self.timeout,
        )
        self._raise_if_auth_expired(resp)
        resp.raise_for_status()
        self.course_context = parse_hidden_inputs(resp.text)

    def fetch_cart_courses(self) -> list[CartCourse]:
        open_resp = self.session.post(
            self.url(f"{CART_PATH}?time={now_ms()}&gnmkdm={GNMKDM}"),
            headers=self.ajax_headers(),
            data={},
            timeout=self.timeout,
        )
        self._raise_if_auth_expired(open_resp)
        open_resp.raise_for_status()

        payload = {
            "xkxnm": self.course_context.get("xkxnm", "2026"),
            "xkxqm": self.course_context.get("xkxqm", "3"),
            "_search": "false",
            "nd": str(now_ms() + random.randint(0, 999)),
            "queryModel.showCount": "100",
            "queryModel.currentPage": "1",
            "queryModel.sortName": "zjsj+",
            "queryModel.sortOrder": "asc",
            "time": "0",
        }
        query_resp = self.session.post(
            self.url(f"{CART_PATH}?doType=query&gnmkdm={GNMKDM}"),
            headers=self.ajax_headers(),
            data=payload,
            timeout=self.timeout,
        )
        self._raise_if_auth_expired(query_resp)
        query_resp.raise_for_status()
        return parse_cart_courses(query_resp.json())

    def submit_course(self, course: CartCourse) -> SubmitResult:
        try:
            resp = self.session.post(
                self.url(f"{SUBMIT_PATH}?gnmkdm={GNMKDM}"),
                headers=self.ajax_headers(),
                data={"ids": course.cart_id},
                timeout=self.timeout,
            )
        except requests.Timeout as exc:
            return SubmitResult("retry", f"网络超时: {exc.__class__.__name__}")
        except requests.RequestException as exc:
            return SubmitResult("retry", f"网络异常: {exc.__class__.__name__}")

        if self._looks_like_login_page(resp):
            return SubmitResult("auth_expired", "登录态已失效或被重定向到登录页")

        try:
            payload = resp.json()
        except ValueError:
            return classify_submit_response(None, resp.status_code)
        return classify_submit_response(payload, resp.status_code)

    def _looks_like_login_page(self, resp: requests.Response) -> bool:
        final_url = resp.url or ""
        text_start = resp.text[:1000] if resp.text else ""
        return "login_slogin" in final_url or "csrftoken" in text_start and "yhm" in text_start

    def _looks_like_home_page(self, resp: requests.Response) -> bool:
        final_url = resp.url or ""
        text_start = resp.text[:5000] if resp.text else ""
        return (
            "index_initMenu" in final_url
            or "教学管理信息服务平台" in text_start and "login_slogin" not in final_url
            and "学生" in text_start
        )

    def _raise_if_auth_expired(self, resp: requests.Response) -> None:
        if self._looks_like_login_page(resp):
            raise SniperError("登录态已失效或进入登录页，请重新运行脚本。")

    def _safe_login_failure_hint(self, resp: requests.Response) -> str:
        location = resp.headers.get("Location", "")
        if location:
            return f"HTTP {resp.status_code}, Location={location[:80]}"
        text = resp.text or ""
        soup = BeautifulSoup(text[:5000], "html.parser")
        title = soup.title.get_text(strip=True) if soup.title else ""
        alert = (
            soup.find(class_="alert")
            or soup.find(class_="tips")
            or soup.find(id="tips")
            or soup.find(id="msg")
            or soup.find(id="tipsMsg")
            or soup.find(id="error")
        )
        alert_text = alert.get_text(" ", strip=True) if alert else ""
        scripts = " ".join(script.get_text(" ", strip=True) for script in soup.find_all("script"))
        script_hint = ""
        for marker in ("账号", "密码", "验证码", "短信", "错误", "失败", "锁定"):
            pos = scripts.find(marker)
            if pos >= 0:
                script_hint = scripts[max(0, pos - 40): pos + 80]
                break
        parts = [f"HTTP {resp.status_code}"]
        if title:
            parts.append(f"title={title[:40]}")
        if alert_text:
            parts.append(f"message={alert_text[:80]}")
        if script_hint:
            parts.append(f"script={script_hint[:100]}")
        if "dxyz" in text or "短信" in text:
            parts.append("可能触发短信验证")
        return ", ".join(parts)

    def _check_login_failure_counter(
        self,
        resp: requests.Response,
        hidden: dict[str, str],
        username: str,
        headers: dict[str, str],
    ) -> None:
        try:
            value = resp.json()
        except ValueError:
            return
        if value == "0":
            raise SniperError("登录前检查返回用户不存在。")
        if not isinstance(value, str) or "_" not in value:
            return
        count_text, timestamp_text = value.split("_", 1)
        try:
            count = int(count_text)
            last_failed_at = int(timestamp_text)
            threshold = int(hidden.get("yzcskz", "3") or "3")
            lock_minutes = int(hidden.get("dlsbsdsj", "3") or "3")
        except ValueError:
            return
        if count < threshold:
            return
        locked_until = last_failed_at + lock_minutes * 60_000
        current = now_ms()
        if locked_until > current:
            seconds = max(1, int((locked_until - current) / 1000))
            raise SniperError(f"账号登录失败次数达到限制，请约 {seconds} 秒后再试。")
        update_resp = self.session.post(
            self.url("/jwglxt/xtgl/login_cxUpdateDlsbcs.html"),
            headers=headers,
            data={"yhm": username},
            timeout=self.timeout,
        )
        try:
            if update_resp.json() != "操作成功":
                raise SniperError("登录失败次数清零接口未返回操作成功。")
        except ValueError:
            raise SniperError("登录失败次数清零接口响应格式异常。")

    def _extract_meta_refresh_url(self, html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        meta = soup.find("meta", attrs={"http-equiv": lambda value: str(value).lower() == "refresh"})
        if not meta:
            return ""
        content = meta.get("content", "")
        marker = "url="
        pos = content.lower().find(marker)
        return content[pos + len(marker):].strip() if pos >= 0 else ""

    def _follow_login_redirects(self, resp: requests.Response, referer: str) -> bool:
        current = resp
        current_referer = referer
        for _ in range(5):
            location = current.headers.get("Location", "")
            if not location:
                return self._looks_like_home_page(current)
            target = self.url(location)
            next_resp = self.session.get(
                target,
                headers=self.document_headers(current_referer),
                allow_redirects=False,
                timeout=self.timeout,
            )
            next_resp.raise_for_status()
            if "index_initMenu" in location or self._looks_like_home_page(next_resp):
                if next_resp.status_code in (301, 302, 303, 307, 308):
                    final_location = next_resp.headers.get("Location", "")
                    if final_location:
                        final_resp = self.session.get(
                            self.url(final_location),
                            headers=self.document_headers(target),
                            timeout=self.timeout,
                        )
                        final_resp.raise_for_status()
                return True
            current = next_resp
            current_referer = target
            if current.status_code not in (301, 302, 303, 307, 308):
                return self._looks_like_home_page(current)
        return False


def build_course_table(courses: list[CartCourse], show_status: bool = False) -> Table:
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", justify="right", width=4)
    table.add_column("课程")
    table.add_column("教学班")
    table.add_column("类型", width=12)
    table.add_column("学年/学期", width=12)
    table.add_column("加入时间", width=20)
    if show_status:
        table.add_column("次数", justify="right", width=6)
        table.add_column("状态")
        table.add_column("最近消息")

    for course in courses:
        row = [
            str(course.index),
            course.name,
            course.class_name,
            course.course_type,
            f"{course.year}/{course.term}",
            course.joined_at,
        ]
        if show_status:
            row.extend([str(course.attempts), course.status, course.last_message or "-"])
        table.add_row(*row)
    return table


def build_live_panel(courses: list[CartCourse], end_time: float, profile: str) -> Panel:
    remaining = max(0, int(end_time - time.monotonic()))
    active = sum(1 for course in courses if course.active)
    title = f"抢课中 | 档位 {profile} | 剩余 {remaining}s | 活跃 {active}"
    return Panel(build_course_table(courses, show_status=True), title=title, border_style="cyan")


def prompt_full_course(course: CartCourse, console: Console) -> bool:
    console.print()
    console.print(Panel.fit(
        f"{safe_course_line(course)}\n返回原因: {course.last_message}",
        title="课程容量提示",
        border_style="yellow",
    ))
    return Confirm.ask("是否继续抢这门课捡漏？", default=True, console=console)


def run_sniper(client: ScauClient, courses: list[CartCourse], config: Config, console: Console) -> None:
    interval = config.interval_seconds
    end_time = time.monotonic() + config.duration_seconds
    spinner_frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    spin_index = 0

    with Live(build_live_panel(courses, end_time, config.speed_profile), console=console, refresh_per_second=4) as live:
        try:
            while time.monotonic() < end_time and any(course.active for course in courses):
                for course in courses:
                    if time.monotonic() >= end_time:
                        break
                    if not course.active:
                        continue

                    course.attempts += 1
                    course.status = f"提交中 {spinner_frames[spin_index % len(spinner_frames)]}"
                    spin_index += 1
                    live.update(build_live_panel(courses, end_time, config.speed_profile))

                    result = client.submit_course(course)
                    course.last_message = result.message

                    if result.category == "success":
                        course.status = "成功"
                        course.success = True
                        course.active = False
                    elif result.category == "full":
                        course.status = "满课/容量满"
                        live.update(build_live_panel(courses, end_time, config.speed_profile))
                        live.stop()
                        keep_trying = prompt_full_course(course, console)
                        live.start(refresh=True)
                        if keep_trying:
                            course.status = "继续捡漏"
                            course.active = True
                        else:
                            course.status = "已暂停"
                            course.active = False
                    elif result.category == "retry":
                        course.status = "重试中"
                    elif result.category == "auth_expired":
                        course.status = "登录失效"
                        raise SniperError(result.message)
                    else:
                        course.status = "业务停止"
                        course.active = False

                    live.update(build_live_panel(courses, end_time, config.speed_profile))
                    if interval:
                        time.sleep(interval)
        except KeyboardInterrupt:
            for course in courses:
                if course.active:
                    course.status = "用户停止"
                    course.active = False
            live.update(build_live_panel(courses, end_time, config.speed_profile))
            console.print("\n已收到 Ctrl+C，正在汇总当前状态。")


def print_summary(courses: list[CartCourse], console: Console) -> None:
    console.print()
    console.print(Panel(build_course_table(courses, show_status=True), title="最终汇总", border_style="green"))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SCAU 意向购物车抢课脚本")
    parser.add_argument("--config", default=None, help="配置文件路径，默认使用程序同目录 config.json")
    parser.add_argument("--base-url", default=BASE_URL, help="教务系统 Base URL")
    parser.add_argument("--timeout", type=float, default=10.0, help="单个 HTTP 请求超时秒数")
    parser.add_argument("--self-test", action="store_true", help="运行本地自检，不访问教务系统")
    parser.add_argument("--no-pause", action="store_true", help="exe 运行结束时不等待回车")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    console = Console()

    exit_code = 0
    should_pause = getattr(sys, "frozen", False) and not args.no_pause

    try:
        if args.self_test:
            run_self_test(console)
            return 0

        config_path = Path(args.config) if args.config else default_config_path()
        config = load_config(config_path)
        console.print(Panel.fit(
            f"持续时间: {config.duration_seconds}s\n"
            f"速度档位: {config.speed_profile} ({config.interval_seconds}s/请求)\n"
            f"配置文件: {config_path}\n"
            "SCAU-course-tool_v2.0",
            title="配置",
            border_style="cyan",
        ))

        username = Prompt.ask("请输入学号/账号", console=console)
        password = Prompt.ask("请输入密码", console=console, password=False)
        if not username.strip() or not password:
            raise SniperError("账号和密码不能为空。")

        client = ScauClient(base_url=args.base_url, timeout=args.timeout)
        with console.status("正在登录并读取意向购物车...", spinner="dots"):
            client.login(username.strip(), password)
            client.open_course_index()
            courses = client.fetch_cart_courses()

        password = ""
        if not courses:
            console.print("[yellow]当前意向购物车为空，没有可抢课程。[/yellow]")
            return 0

        console.print(Panel(build_course_table(courses), title="当前意向购物车", border_style="cyan"))
        if not Confirm.ask("是否开始抢课？", default=False, console=console):
            console.print("已取消，未发送抢课请求。")
            return 0

        run_sniper(client, courses, config, console)
        print_summary(courses, console)
        return 0
    except SniperError as exc:
        console.print(f"[red]错误：{exc}[/red]")
        exit_code = 2
    except requests.RequestException as exc:
        console.print(f"[red]网络错误：{exc.__class__.__name__}[/red]")
        exit_code = 3
    except Exception as exc:
        console.print(f"[red]未预期错误：{exc.__class__.__name__}: {exc}[/red]")
        exit_code = 1
    finally:
        if should_pause and not args.self_test:
            try:
                console.print()
                input("按回车键退出...")
            except EOFError:
                pass
    return exit_code


def default_config_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().with_name("config.json")
    return Path(__file__).resolve().with_name("config.json")


def run_self_test(console: Console) -> None:
    key = RSA.generate(1024)
    modulus_b64 = base64.b64encode(int(key.n).to_bytes((key.n.bit_length() + 7) // 8, "big")).decode("ascii")
    exponent_b64 = base64.b64encode(int(key.e).to_bytes((key.e.bit_length() + 7) // 8, "big")).decode("ascii")
    encrypted = encrypt_password("secret", modulus_b64, exponent_b64)
    assert isinstance(encrypted, str) and encrypted
    encrypted_jsbn = encrypt_password_jsbn_style("secret", modulus_b64, exponent_b64)
    assert isinstance(encrypted_jsbn, str) and encrypted_jsbn

    encoded = urlencode([("mm", "a"), ("mm", "b")])
    assert encoded == "mm=a&mm=b"

    cart = parse_cart_courses(
        {
            "items": [
                {
                    "row_id": 2,
                    "xkgwcb_id": "cart-2",
                    "kcmc": "B",
                    "jxbmc": "class-b",
                    "kklxmc": "板块课",
                    "zjsj": "2026-06-16 18:45:37",
                    "xnm": "2026",
                    "xqm": "3",
                },
                {
                    "row_id": 1,
                    "xkgwcb_id": "cart-1",
                    "kcmc": "A",
                    "jxbmc": "class-a",
                    "kklxmc": "板块课",
                    "zjsj": "2026-06-16 18:39:12",
                    "xnm": "2026",
                    "xqm": "3",
                },
            ]
        }
    )
    assert [course.name for course in cart] == ["A", "B"]

    assert classify_submit_response([{"flag": "1", "msg": "选课成功"}]).category == "success"
    assert classify_submit_response([{"flag": "0", "msg": "不在选课时间内！"}]).category == "retry"
    assert classify_submit_response([{"flag": "0", "msg": "人数已满"}]).category == "full"
    assert classify_submit_response([{"flag": "0", "msg": "时间冲突"}]).category == "stop"
    assert classify_submit_response(None, 500).category == "retry"

    console.print("[green]本地自检通过：RSA、重复字段、购物车解析、结果分类均正常。[/green]")


if __name__ == "__main__":
    sys.exit(main())
