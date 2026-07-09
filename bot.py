import os
import logging
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
import triage as triager
import cascade
import ocr

logging.basicConfig(level=logging.INFO)
# httpx logs full request URLs which include the bot token — suppress to avoid
# token exposure in journald and any downstream log aggregators
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔍 *triage-local* is ready.\n\n"
        "Send me:\n"
        "• A pasted alert (text)\n"
        "• A screenshot of an alert (photo)\n\n"
        "I'll triage it locally. Critical or low-confidence alerts escalate to Claude with PII scrubbed first.",
        parse_mode="Markdown",
    )


async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    alert_text = update.message.text
    if not alert_text or len(alert_text) < 10:
        await update.message.reply_text("Send me an alert to triage.")
        return

    msg = await update.message.reply_text("⏳ Triaging locally...")

    result = triager.triage(alert_text)
    escalated = False
    claude_analysis = None

    needs_escalation, reason = cascade.should_escalate(result)
    if needs_escalation:
        await msg.edit_text(f"⏳ Low confidence locally ({reason}) — escalating to Claude with PII scrubbed...")
        claude_analysis = cascade.escalate_to_claude(alert_text, result)
        escalated = True

    formatted = triager.format_result(result, escalated=escalated)
    await msg.edit_text(formatted, parse_mode="Markdown")

    if claude_analysis:
        await update.message.reply_text(
            f"☁️ *Claude Analysis:*\n{claude_analysis}", parse_mode="Markdown"
        )


async def handle_photo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg = await update.message.reply_text("📸 Extracting text from image...")

    photo = update.message.photo[-1]  # highest resolution
    file = await ctx.bot.get_file(photo.file_id)
    image_bytes = await file.download_as_bytearray()

    alert_text = ocr.image_to_text(bytes(image_bytes))
    if not alert_text:
        await msg.edit_text("❌ Could not extract text from image.")
        return

    await msg.edit_text(f"📋 Extracted text, triaging...\n\n`{alert_text[:300]}...`", parse_mode="Markdown")

    result = triager.triage(alert_text)
    escalated = False
    claude_analysis = None

    needs_escalation, reason = cascade.should_escalate(result)
    if needs_escalation:
        claude_analysis = cascade.escalate_to_claude(alert_text, result)
        escalated = True

    formatted = triager.format_result(result, escalated=escalated)
    await msg.edit_text(formatted, parse_mode="Markdown")

    if claude_analysis:
        await update.message.reply_text(
            f"☁️ *Claude Analysis:*\n{claude_analysis}", parse_mode="Markdown"
        )


def run():
    token = os.getenv("TELEGRAM_TOKEN")
    if not token:
        raise ValueError("TELEGRAM_TOKEN not set in environment")

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))

    logger.info("triage-local bot starting...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    run()
