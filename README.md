<div align="center">

# Real-TunnelBench

**تست زندهٔ کانفیگ‌ها + رتبه‌بندی مخصوص اپراتورهای ایرانی**

[English](#english) · [فارسی](#فارسی)

</div>

---

# فارسی

`Real-TunnelBench` یک **اکشن گیت‌هاب** است که یک لینک لیست کانفیگ (مثل
[لیست vless](https://github.com/barry-far/V2ray-Config/blob/main/Splitted-By-Protocol/vless.txt))
را می‌گیرد، **تک‌تک کانفیگ‌ها را واقعاً تست می‌کند**، آن‌هایی را که
واقعاً کار می‌کنند و سرعت خوبی دارند پیدا می‌کند، و در نهایت:

| خروجی | توضیح |
| --- | --- |
| `working_configs.txt` | سابscription به صورت base64 — مستقیم قابل استفاده در v2rayN / v2rayNG / Streisand |
| `working_configs_plain.txt` | لیست خام URI ها (هر خط یک کانفیگ) |
| `alive_configs.txt` | تمام کانفیگ‌های زنده (حتی اگر کند باشند) |
| `configs_ranked.csv` | رتبه‌بندی کامل با تأخیر، سرعت، کشور خروجی و امتیاز ایران |
| `results.json` | خروجی ماشین‌خوان برای پردازش بعدی |
| `report.pdf` | گزارش PDF حرفه‌ای با نمودار، تحلیل خطاها و بخش «واکنش‌پذیری در ایران» |
| `summary.md` | خلاصهٔ دوزبانه (فارسی/انگلیسی) |

## چرا این متفاوت است؟

اکشن‌های مشابه فقط **متن** را بررسی می‌کنند. این پروژه کانفیگ‌ها را در یک
**هستهٔ واقعی پروکسی** (sing-box) بالا می‌آورد، برای هر کدام یک inbound
SOCKS می‌سازد و از داخل تونل:

- **تأخیر** (TTFB و RTT) را چند بار اندازه می‌گیرد،
- **سرعت دانلود واقعی** را می‌سنجد،
- **آی‌پی خروجی** و کشور/ASN آن را درمی‌آورد،
- و مشخص می‌کند کدام کانفیگ **برای اپراتور ایرانی** مناسب است.

## اجرای سریع

۱. در تب **Actions** روی «Real-TunnelBench Analysis» کلیک کنید.
۲. **Run workflow** را بزنید.
۳. لینک لیست کانفیگ را در `source_url` paste کنید (مثلاً همان لینک vless).
۴. بعد از پایان، از بخش **Artifacts** فایل `real-tunnelbench-report` را دانلود کنید.

<div align="center">

```yaml
- name: Run Real-TunnelBench
  uses: Reza-Basafa/Real-TunnelBench@main
  with:
    source_url: https://github.com/barry-far/V2ray-Config/blob/main/Splitted-By-Protocol/vless.txt
    output_dir: output
    max_configs: 400
    iran_probe: auto
```

</div>

## ورودی‌ها

| ورودی | پیش‌فرض | توضیح |
| --- | --- | --- |
| `source_url` | ‎— | لینک عمومی لیست کانفیگ (متن ساده یا سابscription base64) |
| `output_dir` | `output` | مسیر خروجی‌ها |
| `max_configs` | `400` | حداکثر تعداد کانفیگ قابل تست (باقی‌مانده بر اساس امتیاز ایران انتخاب می‌شوند) |
| `concurrency` | `12` | تعداد تست‌های هم‌زمان |
| `timeout_minutes` | `45` | بودجهٔ زمانی کل اجرا |
| `min_speed_mbps` | `0.5` | حداقل سرعت لازم برای خروجی نهایی |
| `max_latency_ms` | `2000` | حداکثر تأخیر مجاز |
| `latency_samples` | `3` | تعداد نمونه‌های تأخیر برای هر کانفیگ |
| `speed_test_bytes` | `5000000` | حجم دانلود در تست سرعت |
| `speed_test_url` | خالی | آدرس سفارشی تست سرعت (`{bytes}` جایگزین می‌شود) |
| `latency_url` | خالی | آدرس سفارشی تست تأخیر |
| `iran_probe` | `auto` | اندازه‌گیری از نقطهٔ دید ایران (`auto`/`on`/`off`) |
| `iran_probe_limit` | `25` | تعداد کاندیداهایی که از ایران تست می‌شوند |
| `core_version` | `1.14.4` | نسخهٔ sing-box استفاده‌شده |
| `core_sha256` | خالی | هش انتظاری آرشیو هسته (اختیاری) |
| `geo_lookup` | `true` | جست‌وجوی کشور/ASN سرور مقصد |
| `dry_run` | `false` | فقط پارس کردن لیست، بدون تست |
| `keep_all_tested` | `false` | خروجی گرفتن از همهٔ کانفیگ‌های زنده |
| `include_failed` | `false` | خروجی گرفتن از کانفیگ‌های خراب هم |
| `max_output` | `0` | سقف تعداد خروجی (۰ = بدون سقف) |
| `weight_speed` / `weight_latency` / `weight_iran` / `weight_stability` | `0.50` / `0.20` / `0.22` / `0.08` | وزن هر محور در امتیاز نهایی |

## خروجی‌های اکشن

`working_configs_path`، `working_configs_plain_path`، `report_path`،
`results_path`، `working_count`، `tested_count`، `alive_count`، `best_mbps`

## «واکنش‌پذیری در ایران» چطور محاسبه می‌شود؟

امتیاز ایران از ترکیب دو سیگنال مستقل ساخته می‌شود:

**۱) تحلیل ایستا (بدون شبکه)**

- محل سرور مقصد: داخل ایران / CDN ایرانی (آروان، پارس‌پک، …) / Cloudflare / CDN جهانی / دیتاسنتر
- شکل اتصال: REALITY (+uTLS) › TLS › بدون رمزنگاری
- ترنسپورت: `ws`/`grpc`/`http` روی یک CDN، پورت‌های استاندارد ۴۴۳
- QUIC/UDP (hysteria2 و tuic) که در محدودیت TCP سالم می‌ماند

**۲) اندازه‌گیری از نقطهٔ دید ایران**

کاندیداهای برتر از طریق **Globalping** از پروب‌های داخل ایران تست می‌شوند؛
این تست تأیید می‌کند که پورت سرور از شبکهٔ ایران واقعاً باز است و RTT
واقعی اپراتور ایرانی را نشان می‌دهد. اگر پروب ایرانی در دسترس نباشد، بخش
ایرانی گزارش شفاف اعلام می‌کند که فقط بر پایهٔ تحلیل ایستا محاسبه شده است.

## اجرای محلی

```bash
python -m pip install -r requirements.txt
python src/bench.py --url "https://example.com/list.txt" --output-dir output
```

## معماری

```
src/tunnelbench/
├── uris.py       پارسر vless/vmess/trojan/ss/hysteria2/tuic/socks/http
├── fetch.py      دانلود امن لیست (متن ساده یا base64) + محافظت SSRF
├── singbox.py    تبدیل کانفیگ به outbound سینگ‌باکس
├── core.py       دانلود و مدیریت هستهٔ sing-box
├── httpclient.py کلاینت HTTP/SOCKS5 دقیق برای اندازه‌گیری
├── probe.py      سنجش تأخیر، سرعت و آی‌پی خروجی
├── geo.py        جغرافیا، ASN و دسته‌بندی سرور مقصد
├── iran.py       امتیاز ایران + پروب‌های ایرانی (Globalping)
├── scoring.py    امتیاز نهایی
├── report.py     گزارش PDF
└── pipeline.py   هماهنگ‌کنندهٔ کل خط لوله
```

## محدودیت‌ها

- سنجش روی رانر گیت‌هاب انجام می‌شود (خارج از ایران)؛ بنابراین «سرعت»
  گزارش‌شده سرعت رانر است. برای قضاوت دربارهٔ تجربهٔ داخل ایران از امتیاز
  ایران و نتایج پروب ایرانی استفاده کنید.
- کانفیگ‌های رایگان عمومی خیلی زود از کار می‌افتند؛ نتیجهٔ این اجرا فقط
  لحظهٔ اجرا را نشان می‌دهد.
- فقط پروتکل‌هایی که sing-box پشتیبانی می‌کند قابل تست هستند.

---

# English

`Real-TunnelBench` is a GitHub Action that takes a URL of a proxy
configuration list, **actually tests every configuration**, finds the ones
that work and are fast, and exports a v2ray ready subscription plus a
detailed PDF report.

## Highlights

- Real measurement: every configuration is loaded into a real proxy core
  (sing-box), gets its own SOCKS inbound and is measured from the inside of
  the tunnel (latency, jitter, throughput, exit address).
- Iran awareness: the entry server is geolocated and classified, the
  connection shape (REALITY, TLS, CDN, port) is scored, and the best
  candidates are additionally probed from real **Iranian vantage points**.
- Everything is explained: the PDF report contains the methodology, the
  scoring weights, the throughput chart, the failure analysis and the
  Iran affinity section.

## Usage

```yaml
- name: Run Real-TunnelBench
  uses: Reza-Basafa/Real-TunnelBench@main
  with:
    source_url: https://github.com/barry-far/V2ray-Config/blob/main/Splitted-By-Protocol/vless.txt
    output_dir: output
```

Run the workflow manually from the **Actions** tab and download the
`real-tunnelbench-report` artifact.

## Local usage

```bash
python -m pip install -r requirements.txt
python src/bench.py --url "https://example.com/list.txt" --output-dir output
```

## Tests

```bash
python -m pip install pytest
SING_BOX_BINARY=/path/to/sing-box python -m pytest tests -q
```

The integration test starts a local SOCKS5 proxy and a local HTTP server, so
the complete pipeline (including the real core and the PDF report) runs
without touching the internet.

## Disclaimer

Use the tool only with configurations you are allowed to test. Public
configuration lists are shared by third parties and change constantly; a
configuration that works today may be dead tomorrow.

---

<div align="center">
<small>Built for the Iranian community · سنجش زندهٔ کانفیگ با تمرکز بر ایران</small>
</div>
