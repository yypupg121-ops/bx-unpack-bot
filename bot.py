import os
import logging
import tempfile
from pathlib import Path
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters
)
from analyzer import analyze_file, MAX_INPUT_BYTES

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
MAX_DOWNLOAD_BYTES = int(os.getenv("MAX_DOWNLOAD_BYTES", str(20 * 1024 * 1024)))
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO
)
log = logging.getLogger("bx_unpack_bot")

HELP = (
    "🔎 بوت BX Unpack Analyzer\n\n"
    "أرسل ملفًا وسأفحصه تحليلًا ساكنًا، وأحاول فك طبقات الترميز والضغط المعروفة.\n\n"
    "يدعم مبدئيًا: Base64/Base85 الظاهرة، ZIP، gzip، zlib، bzip2، xz، "
    "واستخراج النصوص والتواقيع ومعلومات ELF.\n\n"
    "⚠️ لا يشغّل الملفات ولا يكسر تشفيرًا حقيقيًا مثل AES دون مفتاح. "
    "لا ترفع ملفات تحتوي أسرارًا أو بيانات شخصية."
)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [[InlineKeyboardButton("ℹ️ طريقة الاستخدام", callback_data="help")]]
    await update.effective_message.reply_text(
        HELP, reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def help_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.message.reply_text(HELP)

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    doc = message.document
    if not doc:
        return
    if doc.file_size and doc.file_size > MAX_DOWNLOAD_BYTES:
        await message.reply_text(
            f"حجم الملف أكبر من الحد المسموح ({MAX_DOWNLOAD_BYTES // (1024*1024)} MiB)."
        )
        return

    status = await message.reply_text("⏳ أفحص الملف دون تشغيله...")
    tmp_dir = tempfile.mkdtemp(prefix="bx_unpack_")
    try:
        tg_file = await context.bot.get_file(doc.file_id)
        source_name = Path(doc.file_name or "uploaded_file.bin").name
        source_path = os.path.join(tmp_dir, source_name)
        await tg_file.download_to_drive(custom_path=source_path)

        actual_size = os.path.getsize(source_path)
        if actual_size > MAX_DOWNLOAD_BYTES or actual_size > MAX_INPUT_BYTES:
            await status.edit_text("تم رفض الملف لأن حجمه يتجاوز الحد المسموح.")
            return

        result = analyze_file(source_path, os.path.join(tmp_dir, "analysis"))
        report_path = result["report"]
        archive_path = result["archive"]

        await status.edit_text("✅ اكتمل التحليل الساكن. أرسل التقرير والملفات المستخرجة.")
        with open(report_path, "rb") as f:
            await message.reply_document(
                document=f,
                filename="report.md",
                caption="📄 تقرير التحليل"
            )
        if archive_path and os.path.getsize(archive_path) > 0:
            with open(archive_path, "rb") as f:
                await message.reply_document(
                    document=f,
                    filename="decoded_files.zip",
                    caption="🧩 الطبقات والملفات المستخرجة — بيانات فقط، لم يتم تشغيلها"
                )
    except Exception as exc:
        log.exception("Analysis failed")
        try:
            await status.edit_text("تعذر إكمال التحليل. راجع سجلات الخادم إن كنت المسؤول.")
        except Exception:
            pass
    finally:
        # Best-effort cleanup of temporary uploads and results.
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

async def handle_non_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_message:
        await update.effective_message.reply_text("أرسل الملف كمرفق Document حتى أتمكن من تحليله.")

def main():
    if not BOT_TOKEN:
        raise SystemExit("Missing BOT_TOKEN environment variable.")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CallbackQueryHandler(help_button, pattern="^help$"))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.ALL & ~filters.COMMAND & ~filters.Document.ALL, handle_non_document))
    log.info("BX Unpack Analyzer bot is starting")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
