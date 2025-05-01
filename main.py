# Made By Rv
# Edit anything at your own risk

from pyrogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
import os
import datetime
from pyrogram import Client, filters, idle
import logging
import asyncio
import time
from typing import Tuple
import shlex
from os.path import join, exists
from hachoir.metadata import extractMetadata
from hachoir.parser import createParser
import shutil
import json
import requests
from config import Config
from typing import Optional
from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from pyrogram.errors.exceptions import UserNotParticipant

# enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('log.txt'),
              logging.StreamHandler()],
    level=logging.INFO)

_LOG = logging.getLogger(__name__)


rvbot = Client(
    "rvpaidbot",
    bot_token = Config.BOT_TOKEN,
    api_id = Config.API_ID,
    api_hash = Config.API_HASH,
    max_concurrent_transmissions = 100
)


# {"h:mm": "hh:mm:ss"}

TIME_VALUES_SEC = {"0:30": "420",
               "1:00": "3600",
               "1:30": "5400",
               "2:00": "7200",
               "2:30": "9000",
               "3:00": "10800"}

TIME_VALUES = {"0:30": "00:7:00",
               "1:00": "01:00;00",
               "1:30": "01:30:00",
               "2:00": "02:00:00",
               "2:30": "02:30:00",
               "3:00": "03:00:00"}

TIME_VALUES_STR = {"0:30": "30Min",
               "1:00": "1Hour",
               "1:30": "1hr 30min",
               "2:00": "2Hour",
               "2:30": "2hr 30min",
               "3:00": "3Hour"}

AUTH_USERS = Config.AUTH_USERS

@rvbot.on_message(filters.command(["log", "logs"]) & filters.user(Config.OWNER_ID))
async def get_log_wm(bot, message) -> None:
    try:
        await message.reply_document("log.txt")
    except Exception as e:
        _LOG.info(e)

@rvbot.on_message(filters.command(["help"]) & filters.user(Config.AUTH_USERS))
async def get_help(bot, message) -> None:
    text = """**To record a live link, send your link in the following format:**

`link timestamp`
In this Bot only Non Drm links are supported

**Demo link :**
http://202.125.144.115:8000/play/a00h 00:00:05

Timestamp format: hh:mm:ss

Note: Don't report to the developer if the video duration is incorrect.

This Type Of Links Not Allowed In This Bot Example:- http://208.86.19.13:81/7066.stream/index.m3u8

There will be a time gap to remove time you Have To Buy Subscription /plan For details"""
    
    inline_keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🚨Updates🚨", url="https://t.me/RoyalToonsOfficial"),
                InlineKeyboardButton("👷Support👷", url="https://t.me/rv2006rv")
            ]
        ]
    )

    await message.reply_text(text, reply_markup=inline_keyboard)

@rvbot.on_message(filters.command(["start"]) & filters.user(Config.AUTH_USERS))
async def get_start(bot, message) -> None:
    text = "Hey there! I am a live video recorder bot. I can record live videos using their URL.\n\nNote: Don't report to the developer if the video duration is incorrect. For More Details /help .\n\nMade With Love By @rv2006rv"
    
    inline_keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🚨Updates🚨", url="https://t.me/RoyalToonsOfficial"),
                InlineKeyboardButton("👷Support👷", url="https://t.me/rv2006rv")
            ]
        ]
    )

    await message.reply_text(text, reply_markup=inline_keyboard)

@rvbot.on_message(filters.command(["plan"]) & filters.user(Config.AUTH_USERS))
async def get_plan(bot, message) -> None:
    text = """**Free Plan User**

There will be a time gap to remove time. You have to buy a subscription for more accurate results.

Upgrade your plan to get the following benefit:
- No time gap in recorded videos 
- Recording time will be more than 50 minutes 

🪙 1 Month Plan 🪙 :- Rs.40
 
 💫 3 Months plan💫 :- Rs.140
 
 💎 6 Months Plan 💎 :- Rs.270

To upgrade your plan, please contact the bot owner."""

    inline_keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Contact Owner", url="https://t.me/rv2006rv")
            ]
        ]
    )

    await message.reply_text(text, reply_markup=inline_keyboard)

# Create a lock object
processing_lock = asyncio.Lock()

# Add a dictionary to keep track of user cooldowns
user_cooldowns = {}
    
@rvbot.on_message(filters.regex(pattern=".*http.*") & filters.user(Config.AUTH_USERS))
async def main_func(bot: Client, message: Message) -> None:
    user_id = message.from_user.id
    
    if user_id in user_cooldowns:
        cooldown_time = 0 # 0 minute cooldown
        last_triggered_time = user_cooldowns[user_id]
        current_time = time.time()
        time_elapsed = current_time - last_triggered_time

        if time_elapsed < cooldown_time:
            remaining_time = cooldown_time - time_elapsed
            return await message.reply_text(f"Due To overload You have Time Gap. For No Time Gap Choose Plan From /plan. Please wait for {remaining_time:.1f} seconds before sending another request.")

    # Acquire the lock
    async with processing_lock:
        # Process the user's request here

        # Update the user's last triggered time
        user_cooldowns[user_id] = time.time()
    url_msg = message.text.split(" ")
    if len(url_msg) != 2:
        return await message.reply_text(
            text="""Please send link in below format, check /help to know more

link timestamp(hh:mm:ss)"""
        )
    else:
        msg_ = await message.reply_text("Please wait ....")
        url = url_msg[0]
        timess = str(url_msg[1])

        # Parse the requested recording time
        requested_time = datetime.datetime.strptime(timess, "%H:%M:%S")
        max_time = datetime.datetime.strptime("10:50:00", "%H:%M:%S")

        # Check if the requested time exceeds the 3hr-50-minute limit
        if requested_time > max_time:
            await msg_.edit("Recording time exceeds the 5hr-50-minute limit. For More Duration /plan  buy plan")
            return

        await uploader_main(url, msg_, timess, message)

        # Update the user's last triggered time
        user_cooldowns[user_id] = time.time()
        
@rvbot.on_callback_query(filters.regex("time.*?"))
async def cb_handler_main(bot: Client, cb: CallbackQuery):
    cb_data = cb.data.split("_",1)[1]
    msg = cb.message
    user_link = msg.reply_to_message.text.split(" ")[0]
    await uploader_main(user_link, msg, cb_data)

def getListOfFiles(dirName):
    # create a list of file and sub directories 
    # names in the given directory 
    listOfFile = os.listdir(dirName)
    allFiles = list()
    # Iterate over all the entries
    for entry in listOfFile:
        # Create full path
        fullPath = os.path.join(dirName, entry)
        # If entry is a directory then get the list of files in this directory 
        if os.path.isdir(fullPath):
            allFiles = allFiles + getListOfFiles(fullPath)
        else:
            allFiles.append(fullPath)
                
    return allFiles

async def uploader_main(usr_link: str, msg: Message, cb_data: str, message):
    await msg.edit(text=f"{cb_data} Recording started,\nthis will take time ...",
                   reply_markup=None)
    video_dir_path = join(Config.DOWNLOAD_DIRECTORY, str(time.time()))
    if not os.path.isdir(video_dir_path):
        os.makedirs(video_dir_path)
    video_file_path = join(video_dir_path, str(time.time()) + ".mkv")
    #vide_seconds = int(TIME_VALUES_SEC.get(str(cb_data), None))
    _LOG.info(f"Recording {cb_data} from {usr_link}")
    error_recording_video = (await runcmd(f"ffmpeg -probesize 10000000 -analyzeduration 15000000 -timeout 9000000 -i {usr_link} -t {cb_data} -codec copy -map 0:v -map 0:a -ignore_unknown {video_file_path}"))[1]
    if error_recording_video:
        _LOG.info(error_recording_video)
    set_audio_title_cmd = f'ffmpeg -i "{video_file_path}" -metadata title="CI" -c:v copy -c:a copy "{video_file_path}"'
    await runcmd(set_audio_title_cmd)
    #durat_ion = await get_video_duration(video_file_path)
    '''
    if durat_ion <= vide_seconds:
        data_file = join(video_dir_path, "data_" + str(time.time()) + ".txt")
        while durat_ion <= vide_seconds:
            video_file_ = join(video_dir_path, str(time.time()) + ".mkv")
            fcmd = f"ffmpeg -i {usr_link} -err_detect ignore_err -ss 0 -to {(vide_seconds-durat_ion)+10} -c copy -map 0:v -map 0:a -metadata title="CI" -c:v copy -c:a copy -ignore_unknown {video_file_}"
            _LOG.info(fcmd)
            run_ffmpeg = await runcmd(fcmd)
            durat_ion += await get_video_duration(video_file_)
            if durat_ion >= vide_seconds:
                file_name_strings = ''
                all_video_files = getListOfFiles(video_dir_path)
                for name in all_video_files:
                    file_name_strings += f"file '{name}'\n"
                with open(data_file, "w+") as opned:
                    opned.write(file_name_strings)
                    opned.close()
                new_video_file_path = join(video_dir_path, str(time.time()) + ".mkv")
                merge_cmd = f"""ffmpeg -f concat -safe 0 -i {data_file} -err_detect ignore_err -c copy -map 0:v -map 0:a -metadata title="CI" -c:v copy -c:a copy -ignore_unknown {new_video_file_path}"""
                _LOG.info(merge_cmd)
                run_ffmpeg = (await runcmd(merge_cmd))[1]
                if run_ffmpeg:
                    _LOG.info(run_ffmpeg)
                video_file_path = new_video_file_path
                break
    '''
    if exists(video_file_path):
        try:
            v_duration = await get_video_duration(video_file_path)
            caption = f"{cb_data} Recording done!\n\n**Duration**: {TimeFormatter(v_duration*1000)}\nby @conan830"
            await message.reply_video(
                video=video_file_path,
                caption=caption,
                quote=True,
                progress=progress_for_pyrogram,
                progress_args=(msg, time.time())
            )
        except Exception as e:
            _LOG.info(e)
            await msg.edit(e)
    else:
        if "Connection timed out" in error_recording_video:
            await msg.reply_text(f"Connection timed out with {usr_link}")
        else:
            await msg.reply_text("File not found, try again ...")

    try:
        try:
            # Try to remove dir
            shutil.rmtree(video_dir_path)
        except:
            pass
        await msg.delete()
    except Exception as e:
        _LOG.info(e)
        pass
    
   
async def get_video_duration(input_file):
    metadata = extractMetadata(createParser(input_file))
    total_duration = 0
    if metadata.has("duration"):
        total_duration = metadata.get("duration").seconds
    return total_duration

def create_time_buttons():
    return InlineKeyboardMarkup(
        [[
        InlineKeyboardButton("30min", callback_data=f"time_0:30"),
        InlineKeyboardButton("1Hour", callback_data=f"time_1:00")
        ],[
        InlineKeyboardButton("1Hr 30min", callback_data=f"time_1:30"),
        InlineKeyboardButton("2Hour", callback_data=f"time_2:00")
        ],[
        InlineKeyboardButton("2Hr 30min", callback_data=f"time_2:30"),
        InlineKeyboardButton("3Hr", callback_data=f"time_3:00")
        ]]
    )

async def runcmd(cmd: str) -> Tuple[str, str, int, int]:
    """ run command in terminal """
    args = shlex.split(cmd)
    process = await asyncio.create_subprocess_exec(*args,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    stdout = stdout.decode('utf-8', 'replace').strip()
    stderr = stderr.decode('utf-8', 'replace').strip()
    return (stdout,
            stderr,
            process.returncode,
            process.pid)

async def progress_for_pyrogram(
    current,
    total,
    message,
    start
):
    now = time.time()
    diff = now - start
    if round(diff % 10.00) == 0 or current == total:
        # if round(current / total * 100, 0) % 5 == 0:
        percentage = current * 100 / total
        speed = current / diff
        elapsed_time = round(diff) * 1000
        time_to_completion = round((total - current) / speed) * 1000
        estimated_total_time = elapsed_time + time_to_completion
        comp = "▪️"
        ncomp = "▫️"
        elapsed_time = TimeFormatter(milliseconds=elapsed_time)
        estimated_total_time = TimeFormatter(milliseconds=estimated_total_time)
        pr = ""
        try:
            percentage=int(percentage)
        except:
            percentage = 0
        for i in range(1,11):
            if i <= int(percentage/10):
                pr += comp
            else:
                pr += ncomp
        progress = "Uploading: {}%\n[{}]\n".format(
            round(percentage, 2),
            pr)

        tmp = progress + "{0} of {1}\nSpeed: {2}/sec\nETA: {3}".format(
            humanbytes(current),
            humanbytes(total),
            humanbytes(speed),
            # elapsed_time if elapsed_time != '' else "0 s",
            estimated_total_time if estimated_total_time != '' else "0 s"
        )
        try:
            await message.edit(
                text="{}\n {}".format(
                    tmp
                )
            )
        except:
            pass


def humanbytes(size):
    # https://stackoverflow.com/a/49361727/4723940
    # 2**10 = 1024
    if not size:
        return ""
    power = 2**10
    n = 0
    Dic_powerN = {0: ' ', 1: 'K', 2: 'M', 3: 'G', 4: 'T', 5: 'P', 6: 'E', 7: 'Z', 8: 'Y'}
    while size > power:
        size /= power
        n += 1
    return str(round(size, 2)) + " " + Dic_powerN[n] + 'B'


def TimeFormatter(milliseconds: int) -> str:
    seconds, milliseconds = divmod(int(milliseconds), 1000)
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    tmp = ((str(days) + "d, ") if days else "") + \
        ((str(hours) + "h, ") if hours else "") + \
        ((str(minutes) + "m, ") if minutes else "") + \
        ((str(seconds) + "s, ") if seconds else "") + \
        ((str(milliseconds) + "ms, ") if milliseconds else "")
    return tmp[:-2]

async def StartBot():
    # create download directory, if not exist
    if not os.path.isdir(Config.DOWNLOAD_DIRECTORY):
        os.makedirs(Config.DOWNLOAD_DIRECTORY)
    print("----@rv2006rv----")
    await rvbot.start()
    print("------Bot Started------")
    await idle()
    print("------Bot Stopped------")
    await rvbot.stop()
    print("----------BYE!---------")

if __name__ == "__main__" :
    asyncio.get_event_loop().run_until_complete(StartBot())
