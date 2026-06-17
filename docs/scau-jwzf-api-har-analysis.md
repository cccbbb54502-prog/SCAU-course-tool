# SCAU 教务选课 HAR 接口分析

来源文件：

- `D:\vibe coding\SCAU-course-tool_v2\SCAU-course-tool_v2.0\jwzf.scau.edu.cn.har`
- `D:\vibe coding\SCAU-course-tool_v2\SCAU-course-tool_v2.0\jwzf.scau.edu.cn_login.har`

更新日期：2026-06-17

说明：本文只记录接口结构、参数名、字段含义和实现注意事项。账号、密码、CSRF、Cookie、学号、姓名、学生维度 ID、教学班 ID、购物车 ID 等真实敏感值均不记录，示例中统一使用占位符。

## 1. 基本信息

Base URL：

```text
https://jwzf.scau.edu.cn
```

系统路径：

```text
/jwglxt
```

当前程序使用的选课模块码：

```text
gnmkdm=N253512
```

当前脚本中的核心路径：

| 常量 | 路径 | 用途 |
| --- | --- | --- |
| `LOGIN_PATH` | `/jwglxt/xtgl/login_slogin.html` | 登录页和登录提交 |
| `COURSE_INDEX_PATH` | `/jwglxt/xsxk/zzxkyzb_cxZzxkYzbIndex.html` | 选课首页 |
| `CART_PATH` | `/jwglxt/xsxk/zzxkyzb_cxWdgwcZzxkYzb.html` | 意向购物车页面和列表查询 |
| `SUBMIT_PATH` | `/jwglxt/xsxk/zzxkyzbjk_xkBcZyZzxkYzbFromCart.html` | 从购物车提交选课 |

通用请求头：

```http
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36
Accept-Language: zh-CN,zh;q=0.9
```

Ajax 接口请求头：

```http
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: https://jwzf.scau.edu.cn
Referer: https://jwzf.scau.edu.cn/jwglxt/xsxk/zzxkyzb_cxZzxkYzbIndex.html?gnmkdm=N253512&layout=default
```

登录表单提交请求头的 `Content-Type` 为：

```http
application/x-www-form-urlencoded
```

## 2. 登录链路

当前脚本完整模拟浏览器登录表单流程：先加载登录页获取隐藏字段，再获取 RSA 公钥，用页面同款 jsbn RSA 逻辑加密密码，然后执行登录前检查、清理已有账号状态并提交登录表单。

### 2.1 加载登录页

```http
GET /jwglxt/xtgl/login_slogin.html
```

响应：`text/html`。

需要从 HTML 中解析 `input` 隐藏字段。当前脚本会读取所有 `input` 的 `name` 或 `id` 作为键，`value` 作为值。

关键字段：

| 字段 | 说明 |
| --- | --- |
| `csrftoken` | 登录 CSRF token，提交登录时必带 |
| `language` | 语言，通常为 `zh_CN` |
| `ydType` | 登录表单字段，HAR 中通常为空 |
| `mmsfjm` | 密码是否加密控制字段。当前脚本中如果值不是 `0`，就使用 RSA 加密 |
| `yzcskz` | 登录失败次数阈值，当前脚本用于登录前失败次数检查 |
| `dlsbsdsj` | 登录失败锁定分钟数，当前脚本用于计算等待时间 |
| `dxsyrz` | 短信验证相关控制字段，本次脚本未实现短信验证分支 |

登录页相关 RSA 脚本：

```text
/zftal-ui-v5-1.0.2/assets/plugins/crypto/rsa/jsbn.js
/zftal-ui-v5-1.0.2/assets/plugins/crypto/rsa/prng4.js
/zftal-ui-v5-1.0.2/assets/plugins/crypto/rsa/rng.js
/zftal-ui-v5-1.0.2/assets/plugins/crypto/rsa/rsa.js
/zftal-ui-v5-1.0.2/assets/plugins/crypto/rsa/base64.js
/jwglxt/js/globalweb/login/login.js
```

### 2.2 获取 RSA 公钥

```http
GET /jwglxt/xtgl/login_getPublicKey.html?time=<timestamp_plus_random>&_=<timestamp>
```

当前脚本中的构造方式：

```text
time = now_ms() + random.randint(1, 999)
_ = now_ms()
```

响应：JSON 对象。

```json
{
  "modulus": "<RSA_MODULUS_BASE64>",
  "exponent": "<RSA_EXPONENT_BASE64>"
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `modulus` | RSA 公钥 modulus，base64 格式 |
| `exponent` | RSA 公钥 exponent，base64 格式 |

前端加密逻辑：

```text
rsaKey.setPublic(b64tohex(modulus), b64tohex(exponent))
encrypted = hex2b64(rsaKey.encrypt(plainPassword))
```

实现注意：

- `RSAKey.encrypt` 使用 PKCS#1 v1.5 随机填充，同一密码每次密文可能不同。
- 登录提交时保留两个同名 `mm` 字段，两个值都为加密后的密码。
- 如果登录页隐藏字段 `mmsfjm == "0"`，当前脚本会按明文密码提交，否则使用 RSA 加密结果。

### 2.3 身份信息确认检查

```http
POST /jwglxt/xtgl/yhgl_cxXxqrCheck.html
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
```

参数：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `yhm` | 是 | 用户名/学号 |

响应：JSON boolean。

```json
false
```

当前脚本逻辑：

- 如果响应为 `true`，认为账号触发身份信息确认分支。
- 当前脚本暂不支持该分支，会停止并提示。

### 2.4 查询登录相关信息

```http
POST /jwglxt/xtgl/login_cxDlxgxx.html
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
```

参数：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `yhm` | 是 | 用户名/学号 |

常见响应：

```json
"0_<timestamp-like-value>"
```

当前脚本逻辑：

- 响应为 `"0"` 时，认为登录前检查返回用户不存在。
- 响应形如 `<count>_<last_failed_at>` 时，会结合登录页隐藏字段 `yzcskz`、`dlsbsdsj` 判断账号是否仍处于登录失败锁定时间内。
- 如果失败次数已达到阈值但锁定时间已过，会调用失败次数清零接口。

### 2.5 登录失败次数清零

```http
POST /jwglxt/xtgl/login_cxUpdateDlsbcs.html
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
```

参数：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `yhm` | 是 | 用户名/学号 |

期望响应：

```json
"操作成功"
```

当前脚本只在登录失败次数达到阈值、但锁定时间已经过期时调用该接口。

### 2.6 清理已有账号状态

```http
POST /jwglxt/xtgl/login_logoutAccount.html
```

参数：当前脚本不传表单参数。

响应：HAR 中观察为空字符串。

用途：模拟前端登录流程中的已有账号状态清理。

### 2.7 提交登录

```http
POST /jwglxt/xtgl/login_slogin.html?time=<timestamp>
Content-Type: application/x-www-form-urlencoded
```

参数：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `csrftoken` | 是 | 登录页解析得到的 CSRF token |
| `language` | 是 | 登录页解析得到，默认 `zh_CN` |
| `ydType` | 否 | 登录页解析得到，默认空字符串 |
| `yhm` | 是 | 用户名/学号 |
| `mm` | 是 | 密码字段，提交两次同名字段 |
| `mm` | 是 | 第二个同名密码字段 |

当前脚本用有序键值对列表提交，以保留两个同名 `mm`：

```python
[
    ("csrftoken", csrf),
    ("language", language),
    ("ydType", yd_type),
    ("yhm", username),
    ("mm", encrypted_password),
    ("mm", encrypted_password),
]
```

登录成功判断：

- 收到 `301/302/303/307/308`，并能跟随跳转进入 `/jwglxt/xtgl/index_initMenu.html?...`。
- 或响应本身看起来已经是学生首页。
- 或 `200` 响应中包含 meta refresh，跳转目标是 `index_initMenu`。

登录失败诊断：

- 当前脚本不会记录账号密码。
- 失败时只提取安全提示，例如 HTTP 状态、Location、页面 title、常见提示区域和少量脚本错误片段。
- 如果页面包含 `dxyz` 或“短信”字样，会提示可能触发短信验证。

## 3. 进入选课首页

```http
GET /jwglxt/xsxk/zzxkyzb_cxZzxkYzbIndex.html?gnmkdm=N253512&layout=default
Referer: https://jwzf.scau.edu.cn/jwglxt/xtgl/index_initMenu.html?jsdm=xs
```

响应：`text/html`。

当前脚本用途：

- 验证登录态。
- 解析页面隐藏字段，保存为 `course_context`。
- 后续购物车查询使用 `course_context["xkxnm"]` 和 `course_context["xkxqm"]`，缺省分别为 `2026` 和 `3`。

登录态过期判断：

- 如果响应 URL 包含 `login_slogin`。
- 或响应前段 HTML 中包含 `csrftoken` 和 `yhm`。

## 4. 意向购物车接口

### 4.1 打开购物车页面

```http
POST /jwglxt/xsxk/zzxkyzb_cxWdgwcZzxkYzb.html?time=<timestamp>&gnmkdm=N253512
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
```

参数：当前脚本传空表单。

响应：`text/html`。

用途：先打开“我的购物车/意向课程”页面，保持与前端流程一致。

### 4.2 查询购物车列表

```http
POST /jwglxt/xsxk/zzxkyzb_cxWdgwcZzxkYzb.html?doType=query&gnmkdm=N253512
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
```

当前脚本参数：

| 参数 | 值 | 说明 |
| --- | --- | --- |
| `xkxnm` | `course_context.xkxnm`，默认 `2026` | 选课学年 |
| `xkxqm` | `course_context.xkxqm`，默认 `3` | 选课学期码 |
| `_search` | `false` | jqGrid 查询字段 |
| `nd` | `now_ms() + random.randint(0, 999)` | 时间戳/防缓存字段 |
| `queryModel.showCount` | `100` | 当前脚本一次最多取 100 条 |
| `queryModel.currentPage` | `1` | 当前页 |
| `queryModel.sortName` | `zjsj+` | 按加入时间排序 |
| `queryModel.sortOrder` | `asc` | 升序 |
| `time` | `0` | 固定字段 |

响应：分页 JSON 对象。

```json
{
  "currentPage": 1,
  "items": [
    {
      "row_id": 1,
      "xkgwcb_id": "<CART_ITEM_ID>",
      "kcmc": "课程名称",
      "jxbmc": "教学班名称",
      "zjxbmcs": "教学班名称列表",
      "kklxmc": "开课类型",
      "zjsj": "2026-06-16 18:39:12",
      "xnm": "2026",
      "xqm": "3"
    }
  ],
  "totalResult": 1
}
```

当前脚本使用的字段：

| 字段 | 用途 |
| --- | --- |
| `xkgwcb_id` | 购物车条目 ID，提交选课时作为 `ids` |
| `kcmc` | 课程名称 |
| `jxbmc` / `zjxbmcs` | 教学班名称，优先使用 `jxbmc` |
| `kklxmc` | 开课类型 |
| `zjsj` | 加入购物车时间 |
| `xnm` | 学年 |
| `xqm` | 学期 |
| `row_id` | 排序辅助字段 |

排序规则：

```text
先按 zjsj 升序，再按 row_id 升序。
```

## 5. 提交选课接口

```http
POST /jwglxt/xsxk/zzxkyzbjk_xkBcZyZzxkYzbFromCart.html?gnmkdm=N253512
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
```

用途：从意向购物车提交选课。

参数：

| 参数 | 必填 | 当前脚本用法 |
| --- | --- | --- |
| `ids` | 是 | 单个购物车条目 ID，即 `items[].xkgwcb_id` |

当前脚本是逐门课程提交，不再一次性提交逗号分隔的多个 ID：

```http
ids=<CART_ITEM_ID>
```

HAR 中曾观察到多个 ID 可以用 URL 编码后的逗号分隔：

```http
ids=<CART_ITEM_ID_1>%2C<CART_ITEM_ID_2>
```

但为了能单独判断每门课的结果，当前程序按课程循环提交。

成功或失败响应通常是 JSON 数组：

```json
[
  {
    "flag": "0",
    "msg": "不在选课时间内！",
    "xkgwcb_id": "<CART_ITEM_ID>"
  }
]
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `flag` | 结果标志。当前经验中 `"1"` 表示成功，`"0"` 表示失败 |
| `msg` | 业务结果消息，用于判断成功、满课、可重试或停止 |
| `xkgwcb_id` | 购物车条目 ID，可能返回 |

## 6. 提交结果分类

当前脚本会把提交响应统一分类成 `SubmitResult.category`，后续抢课循环根据分类决定是否继续。

HTTP 状态优先级：

| 条件 | 分类 | 处理 |
| --- | --- | --- |
| `401` 或 `403` | `auth_expired` | 登录态失效，停止整个程序 |
| `>= 500` | `retry` | 服务端临时异常，继续重试 |
| `>= 400` | `stop` | 请求失败，停止当前课程 |

业务响应分类：

| 条件 | 分类 | 处理 |
| --- | --- | --- |
| `flag` 为 `1`、`true`、`success` 等，或消息包含成功关键词 | `success` | 当前课程成功，停止提交该课程 |
| 消息包含满课、已满、容量、名额、余量不足等关键词 | `full` | 当前课程进入满课提示，用户可选择继续蹲或暂停该课程 |
| 消息包含未开始、不在选课时间、系统繁忙、稍后、重试、网络、超时等关键词 | `retry` | 当前课程继续重试 |
| 消息包含冲突、已选、重复、不符合、限制、培养方案、不可选、先修、学分、性别、年级、专业等关键词 | `stop` | 停止当前课程 |
| `flag == "0"` 但未命中上述关键词 | `stop` | 默认按业务失败处理 |
| 响应不是可识别 JSON | `retry` | 临时不可识别，继续重试 |

当前脚本内置自检样例：

```python
assert classify_submit_response([{"flag": "1", "msg": "选课成功"}]).category == "success"
assert classify_submit_response([{"flag": "0", "msg": "不在选课时间内！"}]).category == "retry"
assert classify_submit_response([{"flag": "0", "msg": "人数已满"}]).category == "full"
assert classify_submit_response([{"flag": "0", "msg": "时间冲突"}]).category == "stop"
assert classify_submit_response(None, 500).category == "retry"
```

## 7. 当前程序调用顺序

```text
1. 创建同一个 requests.Session，自动保存 Cookie。
2. GET /jwglxt/xtgl/login_slogin.html
3. 解析 csrftoken、language、ydType、mmsfjm、yzcskz、dlsbsdsj 等隐藏字段。
4. GET /jwglxt/xtgl/login_getPublicKey.html?time=<timestamp_plus_random>&_=<timestamp>
5. 如果 mmsfjm != "0"，使用 jsbn 兼容 RSA 逻辑加密密码。
6. POST /jwglxt/xtgl/yhgl_cxXxqrCheck.html，参数 yhm。
7. POST /jwglxt/xtgl/login_cxDlxgxx.html，参数 yhm，并检查失败次数。
8. 必要时 POST /jwglxt/xtgl/login_cxUpdateDlsbcs.html，参数 yhm。
9. POST /jwglxt/xtgl/login_logoutAccount.html。
10. POST /jwglxt/xtgl/login_slogin.html?time=<timestamp>，提交 csrftoken、language、ydType、yhm、mm、mm。
11. 跟随跳转进入 /jwglxt/xtgl/index_initMenu.html?jsdm=xs...
12. GET /jwglxt/xsxk/zzxkyzb_cxZzxkYzbIndex.html?gnmkdm=N253512&layout=default
13. POST /jwglxt/xsxk/zzxkyzb_cxWdgwcZzxkYzb.html?time=<timestamp>&gnmkdm=N253512
14. POST /jwglxt/xsxk/zzxkyzb_cxWdgwcZzxkYzb.html?doType=query&gnmkdm=N253512
15. 从 items[].xkgwcb_id 取得待提交购物车条目 ID。
16. 对每一门 active 课程循环 POST /jwglxt/xsxk/zzxkyzbjk_xkBcZyZzxkYzbFromCart.html?gnmkdm=N253512。
17. 根据提交结果分类决定成功、满课提示、继续重试、登录失效或停止当前课程。
```

## 8. HAR 中存在但当前脚本不依赖的接口

这些接口在页面初始化或筛选时可能出现，但当前抢课脚本的最小链路不依赖它们。

### 8.1 选课展示初始化

```http
POST /jwglxt/xsxk/zzxkyzb_cxZzxkYzbDisplay.html?gnmkdm=N253512
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
```

常见参数：

| 参数 | 说明 |
| --- | --- |
| `xkkz_id` | 选课控制 ID |
| `kklxdm` | 开课类型码，HAR 中为 `06` |
| `xszxzt` | 学生选课状态 |
| `njdm_id` | 年级代码 |
| `zyh_id` | 专业代码 |
| `kspage` | 起始页 |
| `jspage` | 结束页 |

### 8.2 已选课程展示

```http
POST /jwglxt/xsxk/zzxkyzb_cxZzxkYzbChoosedDisplay.html?gnmkdm=N253512
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
```

常见参数包括：

```text
jg_id, zyh_id, njdm_id, zyfx_id, bh_id, xz, ccdm, xqh_id, xkxnm, xkxqm, xkly
```

### 8.3 学生选课提示状态

```http
POST /jwglxt/xsxk/zzxkyzb_cxXsXktsxx.html?gnmkdm=N253512
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
```

常见参数：

```text
xkxnm, xkxqm, kklxdm, njdm_id, zyh_id, bh_id, zyfx_id
```

HAR 中观察响应示例：

```json
"1"
```

### 8.4 筛选字典接口

| 接口 | 说明 |
| --- | --- |
| `/jwglxt/xkgl/common_queryXquListPaged.html?gnmkdm=N253512` | 校区列表 |
| `/jwglxt/xkgl/common_queryKcgsPaged.html?gnmkdm=N253512` | 课程归属/课程系列 |
| `/jwglxt/xtgl/comm_cxJcsjList.html?lxdm=0036&gnmkdm=N253512` | 星期字典 |
| `/jwglxt/xkgl/common_querySkjcList.html?gnmkdm=N253512` | 上课节次列表 |

## 9. 已知限制

1. 当前 HAR 包含登录、购物车查询和从购物车提交选课链路，不包含“加入意向/加入购物车”的完整接口。
2. HAR 中提交选课时返回“不在选课时间内”，没有真实成功提交时的完整响应样本。当前成功判断基于 `flag` 和成功关键词。
3. 短信验证分支在前端源码中存在，但当前 HAR 未触发，脚本也未实现该分支。
4. 当前脚本依赖同一个 HTTP session 自动保存 Cookie，不需要也不应该手动记录 Cookie 值。
5. 当前脚本不会把账号密码写入本地配置或日志。密码只在内存中用于登录加密，登录后会清空变量引用。
6. `config.json` 只控制抢课持续时间和速度档位，不包含账号密码。
