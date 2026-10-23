# BX Unpack Analyzer Telegram Bot

بوت تيليجرام للتحليل الساكن وفك طبقات تغليف/ترميز معروفة. لا يشغّل الملفات المرفوعة.

## 1) إنشاء بوت تيليجرام
1. افتح `@BotFather`.
2. أرسل `/newbot` واتبع التعليمات.
3. انسخ التوكن. لا ترسله لأي شخص ولا تضعه داخل الكود.

## 2) تشغيل محلي للاختبار
يتطلب Python 3.10+:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export BOT_TOKEN="ضع_توكن_البوت_هنا"
python bot.py
```
في PowerShell استخدم:
```powershell
$env:BOT_TOKEN="ضع_توكن_البوت_هنا"
python bot.py
```

## 3) النشر على Railway
1. ارفع محتويات هذا المجلد إلى مستودع GitHub جديد.
2. في Railway أنشئ مشروعًا من المستودع.
3. أضف متغير البيئة `BOT_TOKEN` من إعدادات Variables.
4. تأكد أن Start Command هو `python bot.py` أو استخدم Procfile كـ Worker.
5. استخدم خدمة Worker/عملية دائمة، وليس خدمة ويب لا تحتاج منفذ HTTP.
6. راقب Logs حتى ترى أن البوت بدأ. لا تشارك التوكن في السجلات أو المحادثات.

## 4) النشر على VPS
ثبت Python 3.10+ ثم:
```bash
sudo apt update
sudo apt install -y python3 python3-venv
sudo mkdir -p /opt/bx-unpack-bot
sudo chown "$USER":"$USER" /opt/bx-unpack-bot
# انسخ ملفات المشروع إلى /opt/bx-unpack-bot
cd /opt/bx-unpack-bot
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```
أنشئ ملف بيئة سري:
```bash
sudo nano /etc/bx-unpack-bot.env
```
ضع داخله:
```text
BOT_TOKEN=ضع_توكن_البوت_هنا
```
ثم:
```bash
sudo chmod 600 /etc/bx-unpack-bot.env
sudo nano /etc/systemd/system/bx-unpack-bot.service
```
محتوى خدمة systemd (عدّل `User` و`WorkingDirectory` حسب حسابك):
```ini
[Unit]
Description=BX Unpack Analyzer Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/bx-unpack-bot
EnvironmentFile=/etc/bx-unpack-bot.env
ExecStart=/opt/bx-unpack-bot/.venv/bin/python /opt/bx-unpack-bot/bot.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/bx-unpack-bot

[Install]
WantedBy=multi-user.target
```
ثم:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bx-unpack-bot
sudo systemctl status bx-unpack-bot
journalctl -u bx-unpack-bot -f
```
غيّر `User=ubuntu` إلى مستخدم موجود عندك، ولا تشغّله بصلاحية root.

## حدود النسخة الأولى
- فك طبقات Base64/Base85 وZIP وgzip/zlib/bzip2/xz المعروفة.
- تحليل ساكن للتواقيع والنصوص وبنية ELF الأساسية.
- لا تنفذ `exec` أو `eval` أو `import` للملف المرفوع.
- لا تكسر تشفيرًا بمفتاح، ولا تستعيد المصدر الأصلي من ملف ELF مضمونًا.
- الحد الافتراضي للملف 20 MiB؛ خرج الطبقة 16 MiB؛ مجموع الخرج 48 MiB؛ عمق 5.
- قبل إتاحة البوت للعموم، أضف حدًا لكل مستخدم، ومجلد عمل معزولًا، ومراقبة استخدام الموارد، وسياسة حذف مناسبة.
