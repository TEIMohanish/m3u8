import os, time, logging, random, shlex, shutil, asyncio, datetime
from typing import Tuple
from os.path import join, exists
from hachoir.metadata import extractMetadata
from hachoir.parser import createParser
from pyrogram import Client, filters, idle
from pyrogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from config import Config

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

rvbot = Client("recorder", bot_token=Config.BOT_TOKEN, api_id=Config.API_ID, api_hash=Config.API_HASH)
processing_lock = asyncio.Lock()

user_metadata = {}
user_prefix = {}
user_status = {}
user_tasks = {}

DEFAULT_METADATA = "ToonEncodes"

@rvbot.on_message(filters.command("start") & filters.user(Config.AUTH_USERS))
async def start(bot, message):
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📖 Help", callback_data="help")],
        [InlineKeyboardButton("💠 Plans", callback_data="plan")],
        [InlineKeyboardButton("📢 Channel", url="https://t.me/ToonEncodesIndia")]
    ])
    await message.reply_text(
        "**👋 Welcome!**\nSend a link like:\n`http://link 00:00:00 filename`\n\nUse /help for details.",
        reply_markup=kb
    )

@rvbot.on_message(filters.command("setmetadata") & filters.user(Config.AUTH_USERS))
async def setmeta(bot, message):
    parts = message.text.split(" ", 1)
    if len(parts) != 2:
        return await message.reply("Usage: /setmetadata TitleHere")
    user_metadata[message.from_user.id] = parts[1]
    await message.reply(f"✅ Metadata title set to: `{parts[1]}`")

@rvbot.on_message(filters.command("setprefix") & filters.user(Config.AUTH_USERS))
async def setprefix(bot, message):
    parts = message.text.split(" ", 1)
    if len(parts) != 2:
        return await message.reply("Usage: /setprefix PrefixHere")
    user_prefix[message.from_user.id] = parts[1]
    await message.reply(f"✅ Filename prefix set to: `{parts[1]}`")

@rvbot.on_message(filters.command("status") & filters.user(Config.AUTH_USERS))
async def status_cmd(bot, message):
    uid = message.from_user.id
    status = user_status.get(uid)
    if not status:
        return await message.reply("ℹ️ No active task.")
    await message.reply_text(
        f"**📊 Status**\n"
        f"🆔 Task ID: {status['id']}\n"
        f"📁 Filename: {status['filename']}\n"
        f"⏱ Duration: {status['progress']} / {status['target']}\n"
        f"👤 By: @{message.from_user.username or 'anonymous'}"
    )

@rvbot.on_message(filters.command("help") & filters.user(Config.AUTH_USERS))
async def help_cmd(bot, message):
    await message.reply_text(
        "**🛠 Help Menu**\n\n"
        "**To start a recording:**\n"
        "`http://link 00:00:00 My Filename`\n\n"
        "**Commands:**\n"
        "• /setmetadata `MyTitle` – Set ffmpeg metadata (default: ToonEncodes)\n"
        "• /setprefix `MyPrefix` – Custom file name prefix\n"
        "• /status – Check your current recording\n"
        "• /start – Welcome screen\n"
        "• /plan – View plans\n"
        "• /tools – Extra tools\n\n"
        "**Notes:**\n"
        "- Link must not be DRM-protected.\n"
        "- Timestamp must be in hh:mm:ss format.\n"
        "- Bot sends file with auto thumbnail and duration.\n"
        "- Make sure filename doesn't use `/\\:*?\"<>|`\n\n"
        "_Bot by @TEMohanish_",
        disable_web_page_preview=True
    )
@rvbot.on_message(filters.command("plan") & filters.user(Config.AUTH_USERS))
async def plan_cmd(bot, message):
    text = (
        "**💠 Subscription Plans**\n\n"
        "**Free Plan:**\n"
        "• ⏳ Time gap between recordings\n"
        "• ⏱ Limited recording length\n\n"
        "**Premium Benefits:**\n"
        "• 🚫 No time gaps\n"
        "• ⏰ Record up to 3–5 hours per task\n"
        "• 🎧 Multi-audio support\n"
        "• ⚡ Faster processing\n\n"
        "**💳 Pricing:**\n"
        "• 🪙 1 Month — ₹40\n"
        "• 💫 3 Months — ₹140\n"
        "• 💎 6 Months — ₹270\n\n"
        "To upgrade, contact the owner below:"
    )

    markup = InlineKeyboardMarkup([
        [InlineKeyboardButton("💬 Contact Owner", url="https://t.me/TEMohanish")],
        [InlineKeyboardButton("📢 Updates", url="https://t.me/ToonEncodesIndia")]
    ])

    await message.reply_text(text, reply_markup=markup)

@rvbot.on_message(filters.regex(r"^http.*? \d{2}:\d{2}:\d{2} .+") & filters.user(Config.AUTH_USERS))
async def handle_record(bot, message: Message):
    user_id = message.from_user.id
    msg = await message.reply_text("⏳ Processing...")

    try:
        url, timestamp, raw_filename = message.text.split(" ", 2)
        title = user_metadata.get(user_id, DEFAULT_METADATA)
        prefix = user_prefix.get(user_id, DEFAULT_METADATA)
        filename = f"[{prefix}] {raw_filename.strip()}.mkv"
        save_dir = join(Config.DOWNLOAD_DIRECTORY, str(time.time()))
        os.makedirs(save_dir, exist_ok=True)
        video_path = join(save_dir, filename)

        user_tasks[user_id] = time.time()
        user_status[user_id] = {"id": int(user_tasks[user_id]), "filename": raw_filename.strip(), "target": timestamp, "progress": "00:00:00"}

        # Record using ffmpeg
        cmd = f'ffmpeg -probesize 10000000 -analyzeduration 15000000 -timeout 9000000 -i "{url}" -map 0:v -map 0:a -c copy -t {timestamp} -ignore_unknown "{video_path}"'
        err = (await runcmd(cmd))[1]
        if err:
            raise Exception(err)

        # Embed metadata
        meta_cmd = f'ffmpeg -i "{video_path}" -metadata title="{title}" -c copy "{video_path}"'
        await runcmd(meta_cmd)

        # Generate random thumbnail
        dur = await get_video_duration(video_path)
        rand_sec = random.randint(5, max(dur - 5, 6))
        thumb_path = join(save_dir, "thumb.jpg")
        await runcmd(f'ffmpeg -ss {rand_sec} -i "{video_path}" -vframes 1 -q:v 2 "{thumb_path}"')

        # Send video
        caption = f"**{raw_filename.strip()}**\n" \
                  f"DURATION: {TimeFormatter(dur * 1000)}\n" \
                  f"Recorded by: @{message.from_user.username or 'anonymous'}"
        start_time = time.time()
        await message.reply_video(
          video=video_path,
          caption=caption,
          thumb=thumb_path,
          progress=progress_for_pyrogram,
          progress_args=(message, start_time)
        )

        await msg.delete()
    except Exception as e:
        LOG.error(f"Error: {e}")
        await msg.edit(f"❌ Error occurred:\n`{str(e)}`")
    finally:
        user_status.pop(user_id, None)
        user_tasks.pop(user_id, None)
        try:
            shutil.rmtree(save_dir)
        except Exception:
            pass


async def runcmd(cmd: str) -> Tuple[str, str, int, int]:
    args = shlex.split(cmd)
    process = await asyncio.create_subprocess_exec(*args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    return stdout.decode(), stderr.decode(), process.returncode, process.pid


async def get_video_duration(input_file: str) -> int:
    metadata = extractMetadata(createParser(input_file))
    return metadata.get("duration").seconds if metadata.has("duration") else 0

async def progress_for_pyrogram(current, total, message, start):
    now = time.time()
    diff = now - start
    if diff == 0:
        diff = 1
    percentage = current * 100 / total
    speed = current / diff
    elapsed = TimeFormatter(int(diff * 1000))
    eta = TimeFormatter(int((total - current) / speed * 1000))
    progress_str = "[{}{}]".format(
        ''.join("█" for _ in range(int(percentage // 10))),
        ''.join("░" for _ in range(10 - int(percentage // 10)))
    )
    text = f"**Uploading...**\n{progress_str} {percentage:.1f}%\n" \
           f"{humanbytes(current)} of {humanbytes(total)}\n" \
           f"Speed: {humanbytes(speed)}/s\nETA: {eta}"
    try:
        await message.edit(text)
    except:
        pass

def humanbytes(size):
    if not size:
        return "0 B"
    power = 2**10
    n = 0
    Dic_powerN = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{round(size, 2)} {Dic_powerN[n]}B"

def TimeFormatter(milliseconds: int) -> str:
    seconds, _ = divmod(int(milliseconds), 1000)
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}"


async def main():
    if not os.path.exists(Config.DOWNLOAD_DIRECTORY):
        os.makedirs(Config.DOWNLOAD_DIRECTORY)
    await rvbot.start()
    print("Bot started...")
    await idle()
    await rvbot.stop()
    print("Bot stopped.")

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
