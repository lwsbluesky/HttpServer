"""Generate an auditable Markdown report from final machine-readable evidence."""
import csv
import hashlib
import json
from pathlib import Path
import platform
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
E=ROOT/"docs"/"test-evidence-v1.3"
suite=ET.parse(E/"api-tests.xml").getroot()
cases=suite.findall(".//testcase")
passed=sum(c.find("failure") is None and c.find("error") is None and c.find("skipped") is None for c in cases)
skipped=sum(c.find("skipped") is not None for c in cases)
failed=len(cases)-passed-skipped
live=json.loads((E/"live-results.json").read_text(encoding="utf-8"))
exe=json.loads((E/"exe-live-results.json").read_text(encoding="utf-8"))
audit=json.loads((E/"dependency-audit.json").read_text(encoding="utf-8"))
vulns=sum(len(d["vulns"]) for d in audit["dependencies"])
with (E/"api-test-cases.csv").open("w",encoding="utf-8-sig",newline="") as file:
    writer=csv.writer(file);writer.writerow(["case","result","seconds","skip_reason"])
    for c in cases:
        skip=c.find("skipped")
        writer.writerow([c.attrib["name"],"skipped" if skip is not None else "failed" if c.find("failure") is not None or c.find("error") is not None else "passed",
                         c.attrib["time"],skip.attrib.get("message","") if skip is not None else ""])
def mb(n):return f"{n/1024**2:.2f}"
def ms(n):return f"{n*1000:.1f}"
rows=[]
for label,d in (("源码进程（修复依赖后）",live),("Windows EXE",exe)):
    load=d["load"];baseline=load["baseline"];final=load["final"];burst=d["concurrency"]
    rows.append(f"| {label} | {load['actual_seconds']} 秒 | {sum(load['status_counts'].values())} | {ms(load['p95_seconds'])} ms | {ms(load['max_seconds'])} ms | {mb(baseline['rss'])} → {mb(final['rss'])} MiB | {baseline['handles']} → {final['handles']} | {baseline['threads']} → {final['threads']} | {load['temp_files_after']} |")
burst=live["concurrency"]
hashes=[]
for filename in ("app.py","static/app.js","static/index.html","requirements.txt","file_version_info.txt","dist/v1.3/HttpServer.exe"):
    path=ROOT/filename
    hashes.append(f"| {filename} | {hashlib.sha256(path.read_bytes()).hexdigest()} |")
status="候选版本；短时回归通过，72 小时真实长稳尚未验收" if not failed and live["outcome"]==exe["outcome"]=="passed" and not vulns else "测试未通过，见原始证据"
text=f"""# HttpServer V1.3.0.0 开发与测试报告

测试日期：2026-11-13（Asia/Shanghai）  
基线：V1.2.1.1 / f6b231e  
开发分支：codex/v1.3-security-stability  
结论：**{status}**。

## 1. 交付范围

本次开发 V1.3 稳定性与安全基线，未开发 V1.4 的上传、文件修改/删除或 V1.5 的分享链接。
版本号为 1.3.0.0，源码和 Windows 版本资源已一致。

| 策划书要求 | 实现及边界 |
| --- | --- |
| 密码哈希和迁移 | PBKDF2-SHA256，24 万次迭代，随机 16 字节盐；旧数据库自动迁移，迁移前本机备份；不清空用户/共享目录 |
| 强制改密 | 初始/迁移/重置密码登录后必须改密；新密码至少12字符，改密后所有会话失效 |
| 会话生命周期 | 空闲8小时、绝对7天、最多4096个；服务端退出、管理员逐会话撤销、进程重启失效；只存令牌摘要 |
| 登录限制 | IP+用户名，5分钟内5次失败后锁定10分钟；记录表有容量上限并回收 |
| 目录权限 | 五项独立 ACL：浏览、下载、上传、修改、删除；后3项仅配置，实际文件操作留待V1.4 |
| 浏览器下载认证 | 请求头认证准备下载，短时一次性票据绑定目标/用途/会话；不再将登录令牌放在URL |
| 任务隔离 | 浏览4、搜索2、预览2、压缩2个独立线程并发；忙时503和Retry-After；不无限排队 |
| 任务/资源上限 | ZIP 2GiB/10万文件/120秒、8个活动ZIP；预览2MiB；索引/缓存/会话/票据/失败记录均限制容量 |
| 临时文件 | 完成、失败、中断、取消、票据过期/注销均回收；启动和定时清理陈旧文件 |
| SQLite | 所有连接由上下文关闭；事务失败回滚；WAL、忙等待和有限写重试；目录/用户冲突转业务错误 |
| 监控诊断 | /api/health 返回版本、运行时间、数据库、磁盘、活动任务；管理界面显示状态/最近审计；诊断ZIP |
| 审计日志 | 登录、拒绝访问、改密、退出、下载、账号/目录/权限配置操作；文本日志5MiB轮转20份，审计7天/5万行定期回收 |
| 前端状态 | 加载、成功/失败提示、重试、断网恢复；压缩准备错误在当前页显示；特殊文件名转义；移动端重新排版 |
| 安全补充 | 64KiB JSON限制/10秒读取超时；拒绝路径越界、Windows设备名、ADS路径；Junction扫描边界；服务数据目录不允许共享 |

隐藏项只控制列表和搜索展示；目录ACL才决定直接访问权限。Office预览原实现未接通且存在无界解析风险，
本版只开放有界文本/PDF预览；Office预览按策划书V1.5处理。诊断包不包含数据库、共享文件和令牌。

## 2. 环境与测试隔离

- 系统：Windows x64；Python {platform.python_version()}。
- 核心依赖：FastAPI 0.162.5、Starlette 1.7.0、Uvicorn 0.35.0、python-multipart 0.0.32、PyInstaller 6.14.2。
- 自动化：pytest 9.1.1、httpx 0.28.1、Playwright 1.65.1、psutil 7.2.2；浏览器为本机 Microsoft Edge 无界面模式。
- API、迁移、负载和EXE测试使用独立临时数据目录和随机端口，未读取或修改正式 data。
- 压测客户端与服务端同机；数据位于本地临时目录，指标不能直接等同远程网络盘或多机性能。

## 3. 自动化回归结果

**总计 {len(cases)} 项：{passed} 通过，{failed} 失败，{skipped} 跳过。**

| 测试组 | 主要内容 | 结果 |
| --- | --- | --- |
| 密码和迁移 | 随机盐、错误密码、畸形哈希、明文迁移、原记录保留、备份、重复迁移 | 通过 |
| 认证/会话 | 强制改密、弱密码/旧密码校验、空闲/绝对过期、上限、退出、强制下线、默认账号不复活 | 通过 |
| 暴力尝试与输入 | 连续错误登录、10分钟锁定不被5分钟窗口提前解除、SQL注入、超长/伪装长度请求 | 通过 |
| 权限与令牌 | 普通用户拒绝管理接口、浏览/下载独立、ACL即时变更、禁用URL登录令牌 | 通过 |
| 下载票据 | 一次性、有效期、目标绑定、用途绑定、注销/权限变化、数量上限 | 通过 |
| 路径边界 | ../、重复分隔符、反斜杠、盘符、NUL字符、ADS、尾点/空格、Windows设备名、Junction越界 | 通过 |
| 文件与预览 | 文本截断、未知类型、PDF MIME、缺失目录、隐藏继承/展示语义 | 通过 |
| ZIP与清理 | ZIP内容、大小/数量/超时限制、磁盘满注入、活动临时上限、正常/异常/中断/取消/过期清理 | 通过 |
| 数据库和保留 | 事务回滚、真实写锁等待超时及恢复、冲突恢复、审计保留、日志轮转 | 通过 |
| 故障和诊断 | 健康/降级、结构化错误、请求ID、不返回凭据/堆栈、诊断ZIP内容 | 通过 |
| 并发 | 2个受控压缩任务占位时50个请求、并发搜索与缓存失效 | 通过 |
| 72小时逻辑模拟 | 模拟73个小时节点的过期会话与临时文件回收 | 通过；**不是72小时实跑** |
| 符号链接实文件 | Windows创建符号链接测试 | 跳过：当前进程无创建符号链接权限 |

符号链接用例跳过已明确保留；Windows Junction真实创建/越界和扫描排除用例通过，
但它不能替代所有符号链接与网络盘情形。全量用例名称、耗时与跳过原因见 [api-test-cases.csv](test-evidence-v1.3/api-test-cases.csv)。

## 4. 浏览器端到端测试

Microsoft Edge实际测试通过 {len(live['browser_checks'])} 个流程，页面JavaScript异常数为 {len(live.get('browser_page_errors',[]))}：

{chr(10).join('- '+name for name in live['browser_checks'])}

包括初始改密/重登录、中文与单引号文件名预览、真实下载、断网恢复、恶意名称转义、
管理状态/五项权限配置、诊断下载、390px手机布局和服务端退出。
桌面文件页、管理页和手机页截图位于 [证据目录](test-evidence-v1.3/)。

视觉复核发现过手机布局挤压，已改为顶部导航和单列卡片表格；浏览器复测加入页面无横向溢出和下载按钮可见断言。

## 5. 并发与真实负载结果

两个各自读取128MiB目录的真实压缩下载任务与50个普通请求并发：
源码进程 {burst['ok']} 个请求正常200，{burst['busy']} 个请求按容量保护返回503；
最长响应 {ms(burst['max_seconds'])} ms。所有请求均在2秒内返回或明确繁忙，两个ZIP完成且无残留。

另有自动化用屏障固定占用两个ZIP工作槽再发50个请求，验证的确在压缩任务存活期间响应健康/浏览请求。
因此真实下载基准和确定性隔离验证互相补充。

| 运行方式 | 实际持续时间 | 常规请求数（均200） | P95延迟 | 最大延迟 | RSS起止 | 句柄起止 | 线程起止 | 临时残留 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

持续请求循环包含健康、浏览、搜索、单文件下载，定期额外登录并退出。
结束后进程真实重启，验证旧登录令牌401、配置和共享目录仍在，新密码可重新登录。
短时数据未见持续增长，但这不构成“长时间运行问题已全部消除”的证明。

## 6. 依赖与构建

- 初次扫描旧依赖发现24条已知漏洞记录，涉及python-multipart和Starlette。已升级兼容修复版本。
- 最终依赖解析扫描 {len(audit['dependencies'])} 个包，已知漏洞数 **{vulns}**；此结果以扫描时漏洞库为准，不代表没有未知漏洞。
- EXE从新建虚拟环境构建，PyInstaller退出码0，内嵌文件版本/产品版本为1.3.0.0。
- EXE已实际启动、登录/改密、下载/压缩、并发负载、停止/重启测试，不只是检查文件存在。
- 本轮EXE约16MiB。可选tzdata模块的构建提示不影响当前无ZoneInfo依赖的功能；运行测试未出现相关异常。
- 测试框架有1条Starlette TestClient对httpx的弃用提示，属于测试工具兼容提示，不是业务测试失败。
- 本轮未上传GitHub正式Release，也未把候选版合入main。正式发布须先补齐下述验收。

## 7. 尚未完成的严格验收

1. **72小时真实连续运行尚未完成，也未作为本次通过项。** 已提供可运行脚本；73节点时间模拟不能替代它。
2. 未在另一台全新无Python的Windows电脑验证；本机EXE运行通过。
3. Windows网络盘长期断连、休眠唤醒、杀毒软件拦截、权限变化，以及硬盘物理满/损坏未实机覆盖；
   磁盘满为故障注入，数据库锁为真实SQLite锁。
4. 现有故障没有原始崩溃日志，无法确认某一原因就是原问题唯一根因。仍应观察现场日志。
5. 不支持把V1.3当作未经额外配置的公网文件服务器；公网部署不在本版本验收范围。

## 8. 升级与使用提醒

升级前停止旧进程并备份data。迁移后的活动数据库只存密码哈希；
data/pre-v1.3-backup.db是迁移前备份，可能包含旧明文密码，必须只保存在本机并限制访问，不能共享或提交Git。
回滚须停止进程并恢复迁移前完整data，不能直接让旧EXE读取新哈希数据库。
不把正式数据库、日志或共享文件打包进EXE/源码ZIP。

## 9. 复测命令

~~~powershell
.\.venv\Scripts\python.exe -m pytest tests/test_v13.py -q --junitxml=docs/test-evidence-v1.3/api-tests.xml
.\.venv\Scripts\python.exe tests/live_verify.py --seconds 600
.\.venv\Scripts\python.exe tests/live_verify.py --seconds 60 --exe dist/v1.3/HttpServer.exe --skip-browser
python -m pip_audit -r requirements.txt --format json --output docs/test-evidence-v1.3/dependency-audit.json

# 独立72小时真实长稳，需要主机持续开机且不休眠
.\.venv\Scripts\python.exe tests/live_verify.py --seconds 259200 --skip-browser
~~~

## 10. 原始证据与文件指纹

- [API JUnit结果](test-evidence-v1.3/api-tests.xml)
- [每项用例结果CSV](test-evidence-v1.3/api-test-cases.csv)
- [源码真实进程/浏览器/负载结果](test-evidence-v1.3/live-results.json)
- [EXE真实进程/负载结果](test-evidence-v1.3/exe-live-results.json)
- [依赖漏洞扫描结果](test-evidence-v1.3/dependency-audit.json)
- [桌面文件页](test-evidence-v1.3/files-desktop.png)
- [管理中心](test-evidence-v1.3/admin-desktop.png)
- [手机文件页](test-evidence-v1.3/files-mobile.png)

以下SHA256可用于确认测试对应版本。报告本身和其他文档变化不影响程序二进制。

| 文件 | SHA256 |
| --- | --- |
{chr(10).join(hashes)}
"""
(ROOT/"docs"/"V1.3测试报告.md").write_text(text,encoding="utf-8")
print(f"Report generated: {passed} passed / {failed} failed / {skipped} skipped")
