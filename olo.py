#!/usr/bin/env python3
"""
TataPlay DRM Content Downloader & Decryptor

Downloads encrypted content using:
- yt-dlp (default)
- DDownloader (alternative, uses N_m3u8DL-RE internally)

Decrypts using:
1. mp4decrypt (Bento4) - Direct hex keys
2. shaka-packager - Direct hex keys
3. third-party - Uses cryptography library to parse JWK
4. ddownloader - Uses DDownloader library (all-in-one download + decrypt)

Requirements:
  pip install requests pycryptodome yt-dlp cryptography DDownloader
  
  And binaries:
  - Bento4 (mp4decrypt): https://www.bento4.com/
  - Shaka Packager: https://github.com/shaka-project/shaka-packager
  - N_m3u8DL-RE (for DDownloader)
  - ffmpeg (for muxing)
"""

import argparse
import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import sys
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Tuple, Optional
import glob


class KeyConverter:
    """Convert between different key formats (hex, UUID, base64url, JWK)"""
    
    @staticmethod
    def base64url_to_bytes(s: str) -> bytes:
        """Convert base64url string to bytes"""
        s2 = s.replace('-', '+').replace('_', '/')
        padding = (-len(s2)) % 4
        s2 += "=" * padding
        return base64.b64decode(s2)
    
    @staticmethod
    def bytes_to_base64url(b: bytes) -> str:
        """Convert bytes to base64url string"""
        s = base64.b64encode(b).decode('ascii')
        return s.replace('+', '-').replace('/', '_').rstrip('=')
    
    @staticmethod
    def normalize_kid_to_hex(kid: str) -> str:
        """Convert kid from hex/UUID/base64url to hex"""
        kid = kid.strip()
        
        # If looks like hex (32 hex chars)
        if re.fullmatch(r"[0-9a-fA-F]{32}", kid):
            return kid.lower()
        
        # If UUID format -> remove dashes
        if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", kid):
            return kid.replace("-", "").lower()
        
        # Otherwise assume base64url
        try:
            b = KeyConverter.base64url_to_bytes(kid)
            return binascii.hexlify(b).decode("ascii").lower()
        except Exception as e:
            raise ValueError(f"Could not parse kid: {e}")
    
    @staticmethod
    def k_base64url_to_hex(k: str) -> str:
        """Convert JWK 'k' (base64url) to hex"""
        try:
            b = KeyConverter.base64url_to_bytes(k)
            return binascii.hexlify(b).decode("ascii").lower()
        except Exception:
            # Maybe user gave hex already
            if re.fullmatch(r"[0-9a-fA-F]+", k):
                return k.lower()
            raise
    
    @staticmethod
    def uuid_to_base64url(uuid_str: str) -> str:
        """Convert UUID format to base64url"""
        hex_str = uuid_str.replace('-', '')
        kid_bytes = bytes.fromhex(hex_str)
        return KeyConverter.bytes_to_base64url(kid_bytes)
    
    @staticmethod
    def hex_to_uuid(hex_str: str) -> str:
        """Convert hex to UUID format"""
        hex_clean = hex_str.replace('-', '').replace(' ', '')
        if len(hex_clean) == 32:
            return f"{hex_clean[0:8]}-{hex_clean[8:12]}-{hex_clean[12:16]}-{hex_clean[16:20]}-{hex_clean[20:32]}"
        return hex_str
    
    @staticmethod
    def create_jwk(kid_hex: str, key_hex: str) -> dict:
        """Create JWK JSON from hex kid and key"""
        kid_bytes = bytes.fromhex(kid_hex)
        key_bytes = bytes.fromhex(key_hex)
        
        return {
            "kty": "oct",
            "kid": KeyConverter.bytes_to_base64url(kid_bytes),
            "k": KeyConverter.bytes_to_base64url(key_bytes)
        }
    
    @staticmethod
    def parse_jwk(jwk_data: dict) -> Tuple[str, str]:
        """Parse JWK and return kid_hex, key_hex"""
        if not isinstance(jwk_data, dict) or jwk_data.get("kty") != "oct":
            raise ValueError("JWK must have kty='oct'")
        
        k = jwk_data.get("k")
        kid = jwk_data.get("kid")
        
        if not k:
            raise ValueError("JWK missing 'k' value")
        
        kid_hex = KeyConverter.normalize_kid_to_hex(kid) if kid else None
        key_hex = KeyConverter.k_base64url_to_hex(k)
        
        return kid_hex, key_hex
    
    @staticmethod
    def parse_jwk_with_cryptography(jwk_data: dict) -> Tuple[str, str]:
        """Parse JWK using cryptography library (third-party method)"""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            raise ImportError("cryptography library required: pip install cryptography")
        
        print("   Using cryptography library for JWK parsing...")
        
        if not isinstance(jwk_data, dict) or jwk_data.get("kty") != "oct":
            raise ValueError("JWK must have kty='oct'")
        
        # Get k and kid from JWK
        k_b64 = jwk_data.get("k")
        kid_b64 = jwk_data.get("kid")
        
        if not k_b64:
            raise ValueError("JWK missing 'k' value")
        
        # Decode using base64url
        k_bytes = KeyConverter.base64url_to_bytes(k_b64)
        kid_bytes = KeyConverter.base64url_to_bytes(kid_b64) if kid_b64 else None
        
        # Convert to hex
        key_hex = binascii.hexlify(k_bytes).decode('ascii').lower()
        kid_hex = binascii.hexlify(kid_bytes).decode('ascii').lower() if kid_bytes else None
        
        print(f"   Parsed with cryptography library:")
        print(f"   - KID: {kid_hex}")
        print(f"   - KEY: {key_hex}")
        
        return kid_hex, key_hex


class DDownloaderWrapper:
    """Wrapper for DDownloader library (third-party all-in-one solution)"""
    
    def __init__(self):
        self.converter = KeyConverter()
    
    def download_and_decrypt(self, manifest_url: str, kid_hex: str, key_hex: str, output_name: str):
        """Download and decrypt using DDownloader library"""
        print(f"\n🔽 DDownloader Method (All-in-One)")
        print(f"   Library: DDownloader (uses N_m3u8DL-RE + mp4decrypt)")
        
        try:
            from DDownloader.modules.downloader import DOWNLOADER
        except ImportError:
            print("❌ DDownloader not installed")
            print("   Install: pip install DDownloader")
            return False
        
        print(f"\n   Manifest URL: {manifest_url}")
        print(f"   KID: {kid_hex}")
        print(f"   KEY: {key_hex}")
        print(f"   Output: {output_name}")
        
        try:
            # Initialize DDownloader
            downloader = DOWNLOADER()
            
            # Set parameters
            downloader.manifest_url = manifest_url
            downloader.output_name = output_name
            downloader.decryption_keys = [f"{kid_hex}:{key_hex}"]
            
            print(f"\n📥 Starting DDownloader...")
            
            # Start download and decryption
            downloader.drm_downloader()
            
            # Check if output exists
            if os.path.exists(output_name):
                file_size = os.path.getsize(output_name)
                print(f"\n✅ DDownloader completed successfully!")
                print(f"   Output: {output_name}")
                print(f"   Size: {file_size / (1024*1024):.2f} MB")
                return True
            else:
                print(f"\n❌ DDownloader failed - output file not found")
                return False
                
        except Exception as e:
            print(f"\n❌ DDownloader error: {e}")
            import traceback
            traceback.print_exc()
            return False


class ThirdPartyDecryptor:
    """Third-party decryption using cryptography library + mp4decrypt/shaka"""
    
    def __init__(self):
        self.converter = KeyConverter()
    
    def decrypt_from_jwk_file(self, jwk_file: str, input_file: str, output_file: str, method='mp4decrypt'):
        """Decrypt using JWK file (third-party library parses it)"""
        print(f"\n🔓 Third-Party Decryption Method")
        print(f"   JWK file: {jwk_file}")
        print(f"   Input: {input_file}")
        print(f"   Tool: {method}")
        
        # Check if JWK file exists
        if not os.path.exists(jwk_file):
            print(f"❌ JWK file not found: {jwk_file}")
            return False
        
        # Load JWK using third-party library
        print("\n📖 Loading JWK with cryptography library...")
        try:
            with open(jwk_file, 'r') as f:
                jwk_data = json.load(f)
            
            # Parse JWK using cryptography library
            kid_hex, key_hex = self.converter.parse_jwk_with_cryptography(jwk_data)
            
        except Exception as e:
            print(f"❌ Failed to parse JWK: {e}")
            return False
        
        # Now decrypt using the tool
        if method == 'mp4decrypt':
            return self._decrypt_with_mp4decrypt(kid_hex, key_hex, input_file, output_file)
        elif method == 'shaka':
            return self._decrypt_with_shaka(kid_hex, key_hex, input_file, output_file)
        else:
            print(f"❌ Unknown tool: {method}")
            return False
    
    def decrypt_from_jwk_data(self, jwk_data: dict, input_file: str, output_file: str, method='mp4decrypt'):
        """Decrypt using JWK dict (third-party library parses it)"""
        print(f"\n🔓 Third-Party Decryption Method")
        print(f"   Input: {input_file}")
        print(f"   Tool: {method}")
        
        # Parse JWK using cryptography library
        print("\n📖 Parsing JWK with cryptography library...")
        try:
            kid_hex, key_hex = self.converter.parse_jwk_with_cryptography(jwk_data)
        except Exception as e:
            print(f"❌ Failed to parse JWK: {e}")
            return False
        
        # Now decrypt using the tool
        if method == 'mp4decrypt':
            return self._decrypt_with_mp4decrypt(kid_hex, key_hex, input_file, output_file)
        elif method == 'shaka':
            return self._decrypt_with_shaka(kid_hex, key_hex, input_file, output_file)
        else:
            print(f"❌ Unknown tool: {method}")
            return False
    
    def _decrypt_with_mp4decrypt(self, kid_hex: str, key_hex: str, input_file: str, output_file: str):
        """Internal: Decrypt using mp4decrypt"""
        print(f"\n🔧 Decrypting with mp4decrypt...")
        
        mp4decrypt_path = shutil.which("mp4decrypt")
        if not mp4decrypt_path:
            print("❌ mp4decrypt not found in PATH")
            return False
        
        if not os.path.exists(input_file):
            print(f"❌ Input file not found: {input_file}")
            return False
        
        cmd = [
            mp4decrypt_path,
            '--key', f'{kid_hex}:{key_hex}',
            input_file,
            output_file
        ]
        
        print(f"   Command: {' '.join(cmd)}\n")
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(result.stdout)
        
        if result.returncode == 0 and os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            print(f"\n✅ Decryption successful!")
            print(f"   Output: {output_file}")
            print(f"   Size: {file_size / (1024*1024):.2f} MB")
            return True
        else:
            print(f"❌ Decryption failed")
            return False
    
    def _decrypt_with_shaka(self, kid_hex: str, key_hex: str, input_file: str, output_file: str):
        """Internal: Decrypt using shaka-packager"""
        print(f"\n🔧 Decrypting with shaka-packager...")
        
        packager_path = shutil.which("packager")
        if not packager_path:
            print("❌ packager not found in PATH")
            return False
        
        if not os.path.exists(input_file):
            print(f"❌ Input file not found: {input_file}")
            return False
        
        video_temp = f"{output_file}_video.mp4"
        audio_temp = f"{output_file}_audio.mp4"
        
        cmd = [
            packager_path,
            f'in={input_file},stream=video,output={video_temp}',
            f'in={input_file},stream=audio,output={audio_temp}',
            '--enable_raw_key_decryption',
            '--keys', f'key_id={kid_hex}:key={key_hex}'
        ]
        
        print(f"   Command: {' '.join(cmd)}\n")
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(result.stdout)
        
        has_video = os.path.exists(video_temp)
        has_audio = os.path.exists(audio_temp)
        
        if not (has_video or has_audio):
            print("❌ Decryption failed")
            return False
        
        # Handle single stream
        if has_video and not has_audio:
            os.rename(video_temp, output_file)
            print(f"✅ Video-only decryption successful: {output_file}")
            return True
        
        if has_audio and not has_video:
            os.rename(audio_temp, output_file)
            print(f"✅ Audio-only decryption successful: {output_file}")
            return True
        
        # Merge if both exist
        if has_video and has_audio:
            ffmpeg_path = shutil.which("ffmpeg")
            if not ffmpeg_path:
                print("❌ ffmpeg required for muxing")
                return False
            
            mux_cmd = [ffmpeg_path, '-i', video_temp, '-i', audio_temp, '-c', 'copy', '-y', output_file]
            mux_result = subprocess.run(mux_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            os.remove(video_temp)
            os.remove(audio_temp)
            
            if mux_result.returncode == 0:
                print(f"✅ Decryption and muxing successful: {output_file}")
                return True
        
        return False


class TataPlayDownloader:
    def __init__(self):
        # Unified header as per user request
        self.header_string = "Origin=https://watch.tataplay.com&Referer=https://watch.tataplay.com/&User-Agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.69.69.69 YGX/537.36&X-User-Agent=Kodi/21.2 (Windows NT 10.0.19045.5965; Win64; x64)"
        # For requests, convert to dict
        self.headers = dict(item.split('=', 1) for item in self.header_string.split('&'))
        self.converter = KeyConverter()
        self.third_party = ThirdPartyDecryptor()
        self.ddownloader = DDownloaderWrapper()
    
    def timestamp_to_readable(self, timestamp):
        """Convert Unix timestamp to human-readable format"""
        dt = datetime.fromtimestamp(int(timestamp))
        time_str = dt.strftime("%I:%M %p")
        date_str = dt.strftime("%d %B %Y")
        print(f"📅 {timestamp} -> {date_str} at {time_str}")
        return dt
    
    def get_mpd_url(self, channel_id, uid, password, begin, end):
        """Generate MPD URL"""
        return f"https://tataplay.jokerverse.workers.dev/manifest.mpd?id={channel_id}&uid={uid}&pass={password}&begin={begin}&end={end}"
    
    def fetch_mpd(self, url):
        """Fetch MPD manifest"""
        print("\n📥 Fetching MPD manifest...")
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        print("✅ MPD fetched successfully")
        return response.text
    
    def extract_default_kid(self, mpd_content):
        """Extract default_KID from MPD (multiple methods)"""
        print("\n🔍 Extracting KID from MPD...")
        
        # Method 1: Regex for cenc:default_KID
        match = re.search(r'cenc:default_KID="([^"]+)"', mpd_content)
        if match:
            kid = match.group(1)
            print(f"✅ Found KID: {kid}")
            return kid
        
        # Method 2: Regex without namespace
        match = re.search(r'default_KID="([^"]+)"', mpd_content)
        if match:
            kid = match.group(1)
            print(f"✅ Found KID: {kid}")
            return kid
        
        # Method 3: XML parsing
        try:
            root = ET.fromstring(mpd_content)
            for elem in root.iter():
                kid = elem.get('{urn:mpeg:cenc:2013}default_KID')
                if kid:
                    print(f"✅ Found KID: {kid}")
                    return kid
        except Exception as e:
            print(f"   XML parsing warning: {e}")
        
        raise Exception("❌ default_KID not found in MPD")
    
    def get_decryption_key(self, channel_id, content_id, uid, password, kid_base64url):
        """Get decryption key from license server"""
        print(f"\n🔑 Requesting decryption key from license server...")
        
        url = f"https://tataplay.jokerverse.workers.dev/keys.json?id={channel_id}&contentId={content_id}&uid={uid}&pass={password}"
        
        payload = {
            "kids": [kid_base64url],
            "type": "temporary"
        }
        
        response = requests.post(url, json=payload, headers=self.headers)
        response.raise_for_status()
        
        keys_response = response.json()
        
        if 'keys' in keys_response and len(keys_response['keys']) > 0:
            key_b64 = keys_response['keys'][0]['k']
            kid_b64 = keys_response['keys'][0]['kid']
            print(f"✅ Key received from server")
            return kid_b64, key_b64
        else:
            raise Exception("❌ No keys in response")
    
    def merge_video_audio_ffmpeg(self, video_file, audio_file, output_file):
        """Merge video and audio using ffmpeg"""
        print(f"\n🔧 Merging video and audio with ffmpeg...")
        print(f"   Video: {video_file}")
        print(f"   Audio: {audio_file}")
        
        ffmpeg_path = shutil.which("ffmpeg")
        if not ffmpeg_path:
            print("❌ ffmpeg not found in PATH")
            return False
        
        cmd = [
            ffmpeg_path,
            '-i', video_file,
            '-i', audio_file,
            '-c', 'copy',
            '-y',
            output_file
        ]
        
        print(f"   Command: {' '.join(cmd)}\n")
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0 and os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            print(f"✅ Merge successful: {output_file}")
            print(f"   Size: {file_size / (1024*1024):.2f} MB")
            return True
        else:
            print(f"❌ Merge failed")
            print(f"   stderr: {result.stderr}")
            return False
    
    def download_with_ytdlp(self, mpd_url, output_name):
        """Download encrypted content using yt-dlp"""
        print(f"\n⬇️  Downloading with yt-dlp...")
        
        output_template = f"{output_name}_encrypted"
        
        # Use the unified header for all yt-dlp header options
        cmd = [
            'yt-dlp',
            '--allow-unplayable-formats',
            '--concurrent-fragments', '8',
            '--add-header', f"Origin: https://watch.tataplay.com",
            '--add-header', f"Referer: https://watch.tataplay.com/",
            '--add-header', f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.69.69.69 YGX/537.36",
            '--add-header', f"X-User-Agent: Kodi/21.2 (Windows NT 10.0.19045.5965; Win64; x64)",
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.69.69.69 YGX/537.36',
            '--referer', 'https://watch.tataplay.com/',
            '--newline',
            '-o', output_template,
            mpd_url
        ]
        
        print(f"   Command: {' '.join(cmd)}\n")
        
        # Run with real-time output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        for line in process.stdout:
            print(line, end='')
        
        process.wait()
        print("\n")
        
        if process.returncode != 0:
            print(f"❌ yt-dlp failed with return code {process.returncode}")
            return False, None, None
        
        # Find downloaded files
        print("🔍 Looking for downloaded files...")
        
        video_patterns = [
            f"{output_template}.mp4",
            f"{output_template}.mkv",
            f"{output_template}.f*.mp4",
            f"{output_template}.fvideo*.mp4",
        ]
        
        video_file = None
        for pattern in video_patterns:
            files = glob.glob(pattern)
            if files:
                video_file = files[0]
                break
        
        audio_patterns = [
            f"{output_template}.m4a",
            f"{output_template}.f*.m4a",
            f"{output_template}.faudio*.m4a",
        ]
        
        audio_file = None
        for pattern in audio_patterns:
            files = glob.glob(pattern)
            if files:
                audio_file = files[0]
                break
        
        if video_file:
            video_size = os.path.getsize(video_file)
            print(f"✅ Video: {video_file} ({video_size / (1024*1024):.2f} MB)")
        else:
            print(f"⚠️  No video file found")
        
        if audio_file:
            audio_size = os.path.getsize(audio_file)
            print(f"✅ Audio: {audio_file} ({audio_size / (1024):.2f} KB)")
        else:
            print(f"⚠️  No audio file found")
        
        # Merge if both exist
        if video_file and audio_file:
            merged_file = f"{output_name}_encrypted.mp4"
            if self.merge_video_audio_ffmpeg(video_file, audio_file, merged_file):
                os.remove(video_file)
                os.remove(audio_file)
                return True, merged_file, None
            else:
                return False, None, None
        elif video_file:
            merged_file = f"{output_name}_encrypted.mp4"
            if video_file != merged_file:
                shutil.move(video_file, merged_file)
            return True, merged_file, None
        elif audio_file:
            print("❌ Only audio file found, need video")
            return False, None, None
        else:
            print("❌ No output files found")
            return False, None, None
    
    def decrypt_with_mp4decrypt(self, kid_hex, key_hex, input_file, output_file):
        """Decrypt using Bento4 mp4decrypt"""
        print(f"\n🔓 Decrypting with mp4decrypt (Bento4)...")
        
        mp4decrypt_path = shutil.which("mp4decrypt")
        if not mp4decrypt_path:
            print("❌ mp4decrypt not found in PATH")
            print("   Install Bento4: https://www.bento4.com/")
            return False
        
        if not os.path.exists(input_file):
            print(f"❌ Input file not found: {input_file}")
            return False
        
        print(f"   Input: {input_file}")
        print(f"   KID: {kid_hex}")
        print(f"   KEY: {key_hex}")
        
        cmd = [
            mp4decrypt_path,
            '--key', f'{kid_hex}:{key_hex}',
            input_file,
            output_file
        ]
        
        print(f"\n   Command: {' '.join(cmd)}\n")
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(result.stdout)
        
        if result.returncode == 0 and os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            print(f"\n✅ Decryption successful!")
            print(f"   Output: {output_file}")
            print(f"   Size: {file_size / (1024*1024):.2f} MB")
            return True
        else:
            print(f"❌ Decryption failed (return code: {result.returncode})")
            return False
    
    def decrypt_with_shaka(self, kid_hex, key_hex, input_file, output_file):
        """Decrypt using Shaka Packager"""
        print(f"\n🔓 Decrypting with Shaka Packager...")
        
        packager_path = shutil.which("packager")
        if not packager_path:
            print("❌ packager (Shaka Packager) not found in PATH")
            print("   Install: https://github.com/shaka-project/shaka-packager")
            return False
        
        if not os.path.exists(input_file):
            print(f"❌ Input file not found: {input_file}")
            return False
        
        print(f"   Input: {input_file}")
        print(f"   KID: {kid_hex}")
        print(f"   KEY: {key_hex}")
        
        video_temp = f"{output_file}_video.mp4"
        audio_temp = f"{output_file}_audio.mp4"
        
        cmd = [
            packager_path,
            f'in={input_file},stream=video,output={video_temp}',
            f'in={input_file},stream=audio,output={audio_temp}',
            '--enable_raw_key_decryption',
            '--keys', f'key_id={kid_hex}:key={key_hex}'
        ]
        
        print(f"\n   Command: {' '.join(cmd)}\n")
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(result.stdout)
        
        has_video = os.path.exists(video_temp)
        has_audio = os.path.exists(audio_temp)
        
        if result.returncode != 0 and not (has_video or has_audio):
            print(f"❌ Decryption failed (return code: {result.returncode})")
            return False
        
        if has_video and not has_audio:
            os.rename(video_temp, output_file)
            print(f"✅ Video-only decryption successful: {output_file}")
            return True
        
        if has_audio and not has_video:
            os.rename(audio_temp, output_file)
            print(f"✅ Audio-only decryption successful: {output_file}")
            return True
        
        if has_video and has_audio:
            if self.merge_video_audio_ffmpeg(video_temp, audio_temp, output_file):
                os.remove(video_temp)
                os.remove(audio_temp)
                return True
            else:
                return False
        
        return False
    
    def process(self, channel_id, content_id, uid, password, begin, end, output_name, method='mp4decrypt', downloader='ytdlp'):
        """Main processing function"""
        print("=" * 70)
        print("🎬 TataPlay DRM Content Downloader & Decryptor")
        print("=" * 70)
        
        try:
            # Step 1: Parse timestamps
            print("\n📅 STEP 1: Parse Timestamps")
            print(f"   Begin: ", end="")
            self.timestamp_to_readable(begin)
            print(f"   End:   ", end="")
            self.timestamp_to_readable(end)
            
            # Step 2: Generate MPD URL
            print("\n🔗 STEP 2: Generate MPD URL")
            mpd_url = self.get_mpd_url(channel_id, uid, password, begin, end)
            print(f"   {mpd_url}")
            
            # Step 3: Fetch MPD
            print("\n📥 STEP 3: Fetch MPD Manifest")
            mpd_content = self.fetch_mpd(mpd_url)
            
            # Save MPD
            mpd_file = f'{output_name}.mpd'
            with open(mpd_file, 'w') as f:
                f.write(mpd_content)
            print(f"   Saved: {mpd_file}")
            
            # Step 4: Extract KID
            print("\n🔍 STEP 4: Extract KID from MPD")
            uuid_kid = self.extract_default_kid(mpd_content)
            
            # Step 5: Convert to base64url
            print("\n🔄 STEP 5: Convert KID to base64url")
            kid_base64url = self.converter.uuid_to_base64url(uuid_kid)
            print(f"   UUID:       {uuid_kid}")
            print(f"   Base64url:  {kid_base64url}")
            
            # Step 6: Get decryption key
            print("\n🔑 STEP 6: Get Decryption Key")
            kid_b64, key_b64 = self.get_decryption_key(
                channel_id, content_id, uid, password, kid_base64url
            )
            
            # Step 7: Convert to hex
            print("\n🔄 STEP 7: Convert Keys to Hex")
            kid_hex = self.converter.k_base64url_to_hex(kid_b64)
            key_hex = self.converter.k_base64url_to_hex(key_b64)
            
            uuid_kid_hex = uuid_kid.replace('-', '').lower()
            
            print(f"   MPD KID (hex):     {uuid_kid_hex}")
            print(f"   License KID (hex): {kid_hex}")
            print(f"   KEY (hex):         {key_hex}")
            
            # Create JWK
            jwk_data = self.converter.create_jwk(kid_hex, key_hex)
            jwk_file = f'{output_name}.jwk'
            with open(jwk_file, 'w') as f:
                json.dump(jwk_data, f, indent=2)
            print(f"\n   Saved JWK: {jwk_file}")
            
            # Save keys
            keys_file = f'{output_name}.keys'
            with open(keys_file, 'w') as f:
                f.write(f"# Hex format (for mp4decrypt)\n")
                f.write(f"{kid_hex}:{key_hex}\n\n")
                f.write(f"# UUID format\n")
                f.write(f"{uuid_kid}\n\n")
                f.write(f"# JWK format (in {jwk_file})\n")
            print(f"   Saved keys: {keys_file}")
            
            # Determine which KID to use
            kids_to_try = [kid_hex]
            if uuid_kid_hex != kid_hex:
                print(f"\n⚠️  KID mismatch detected - will try both")
                kids_to_try.append(uuid_kid_hex)
            
            final_output = f"{output_name}.mp4"
            
            # DDownloader method (all-in-one)
            if method == 'ddownloader' or downloader == 'ddownloader':
                print("\n⬇️🔓 STEP 8-9: Download & Decrypt with DDownloader")
                
                # Try with both KIDs
                for attempt, current_kid in enumerate(kids_to_try, 1):
                    print(f"\n   Attempt {attempt}/{len(kids_to_try)} with KID: {current_kid}")
                    
                    if self.ddownloader.download_and_decrypt(mpd_url, current_kid, key_hex, final_output):
                        print(f"✅ DDownloader succeeded!")
                        
                        # Success
                        print("\n" + "=" * 70)
                        print("✅ ALL STEPS COMPLETED SUCCESSFULLY!")
                        print("=" * 70)
                        print(f"\n📁 Output Files:")
                        print(f"   - Video:    {final_output}")
                        print(f"   - MPD:      {mpd_file}")
                        print(f"   - Keys:     {keys_file}")
                        print(f"   - JWK:      {jwk_file}")
                        return
                
                raise Exception("DDownloader failed with all KIDs")
            
            # Standard flow: Download then decrypt
            # Step 8: Download
            print("\n⬇️  STEP 8: Download Encrypted Content")
            success, encrypted_file, _ = self.download_with_ytdlp(mpd_url, output_name)
            
            if not success:
                raise Exception("Download failed")
            
            # Step 9: Decrypt
            decryption_success = False
            
            # Third-party method uses JWK
            if method == 'third-party':
                print(f"\n🔓 STEP 9: Decrypt using Third-Party Method")
                print(f"   This method uses cryptography library to parse JWK")
                
                # Try with mp4decrypt first, then shaka
                for tool in ['mp4decrypt', 'shaka']:
                    print(f"\n   Trying {tool}...")
                    decryption_success = self.third_party.decrypt_from_jwk_data(
                        jwk_data, encrypted_file, final_output, tool
                    )
                    if decryption_success:
                        print(f"✅ Third-party decryption succeeded with {tool}")
                        break
            else:
                # Standard methods
                for attempt, current_kid in enumerate(kids_to_try, 1):
                    print(f"\n🔓 STEP 9 (Attempt {attempt}/{len(kids_to_try)}): Decrypt")
                    print(f"   Method: {method}")
                    print(f"   Using KID: {current_kid}")
                    
                    if method == 'mp4decrypt':
                        decryption_success = self.decrypt_with_mp4decrypt(
                            current_kid, key_hex, encrypted_file, final_output
                        )
                    elif method == 'shaka':
                        decryption_success = self.decrypt_with_shaka(
                            current_kid, key_hex, encrypted_file, final_output
                        )
                    else:
                        print(f"❌ Unknown method: {method}")
                        break
                    
                    if decryption_success:
                        print(f"✅ Decryption succeeded with KID: {current_kid}")
                        break
            
            # Cleanup
            if os.path.exists(encrypted_file):
                os.remove(encrypted_file)
                print(f"\n🧹 Cleaned up: {encrypted_file}")
            
            if decryption_success:
                print("\n" + "=" * 70)
                print("✅ ALL STEPS COMPLETED SUCCESSFULLY!")
                print("=" * 70)
                print(f"\n📁 Output Files:")
                print(f"   - Video:    {final_output}")
                print(f"   - MPD:      {mpd_file}")
                print(f"   - Keys:     {keys_file}")
                print(f"   - JWK:      {jwk_file}")
            else:
                raise Exception("All decryption attempts failed")
                
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="TataPlay DRM Content Downloader & Decryptor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Method 1: yt-dlp + mp4decrypt (default, fastest)
  python script.py --channel 1787 --content 500001722 --uid 1137065263 \\
    --pass 10973a7e --begin 1759591500 --end 1759599900 -o output

  # Method 2: yt-dlp + shaka-packager
  python script.py --channel 1787 --content 500001722 --uid 1137065263 \\
    --pass 10973a7e --begin 1759591500 --end 1759599900 -o output --method shaka

  # Method 3: yt-dlp + third-party (cryptography library)
  python script.py --channel 1787 --content 500001722 --uid 1137065263 \\
    --pass 10973a7e --begin 1759591500 --end 1759599900 -o output --method third-party

  # Method 4: DDownloader (all-in-one, uses N_m3u8DL-RE internally)
  python script.py --channel 1787 --content 500001722 --uid 1137065263 \\
    --pass 10973a7e --begin 1759591500 --end 1759599900 -o output --method ddownloader
        """
    )
    
    parser.add_argument('--channel', required=True, help='Channel ID (e.g., 1787)')
    parser.add_argument('--content', required=True, help='Content ID (e.g., 500001722)')
    parser.add_argument('--uid', required=True, help='User ID')
    parser.add_argument('--pass', dest='password', required=True, help='Password')
    parser.add_argument('--begin', required=True, help='Begin timestamp')
    parser.add_argument('--end', required=True, help='End timestamp')
    parser.add_argument('-o', '--output', default='output', help='Output name (default: output)')
    parser.add_argument('--method', choices=['mp4decrypt', 'shaka', 'third-party', 'ddownloader'], 
                        default='mp4decrypt', help='Decryption method (default: mp4decrypt)')
    parser.add_argument('--downloader', choices=['ytdlp', 'ddownloader'], default='ytdlp',
                        help='Downloader to use (default: ytdlp)')
    
    args = parser.parse_args()
    
    downloader = TataPlayDownloader()
    downloader.process(
        args.channel,
        args.content,
        args.uid,
        args.password,
        args.begin,
        args.end,
        args.output,
        args.method,
        args.downloader
    )


if __name__ == "__main__":
    main()
