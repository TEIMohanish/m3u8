import base64
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import subprocess
import os
import sys
import re

# === CONFIGURATION ===
MPD_URL = "https://tataplay.jokerverse01.workers.dev/manifest.mpd?id=1787&uid=1137065263&pass=10973a7e&begin=20251003T100000&end=20251003T100100"
LICENSE_URL = "https://tataplay.jokerverse.workers.dev/keys.json?id=138&contentId=400000149&uid=1137065263&pass=10973a7e"
CDM_PATH = "./l3.wvd"

HEADERS = {
    "Origin": "https://watch.tataplay.com",
    "Referer": "https://watch.tataplay.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.69.69.69 YGX/537.36",
    "X-User-Agent": "TiviMate/4.7.0 (Linux; Android 9)"
}

# Output configuration
OUTPUT_DIR = "./downloads"
ENCRYPTED_VIDEO = os.path.join(OUTPUT_DIR, "encrypted_video.mp4")
ENCRYPTED_AUDIO = os.path.join(OUTPUT_DIR, "encrypted_audio.m4a")
DECRYPTED_VIDEO = os.path.join(OUTPUT_DIR, "decrypted_video.mp4")
DECRYPTED_AUDIO = os.path.join(OUTPUT_DIR, "decrypted_audio.m4a")
FINAL_OUTPUT = os.path.join(OUTPUT_DIR, "final_output.mp4")

# === 1. Fetch MPD ===
def fetch_mpd(url):
    print("[*] Fetching MPD...")
    resp = requests.get(url, headers=HEADERS, allow_redirects=True)
    resp.raise_for_status()
    print(f"[+] Final MPD URL: {resp.url}")
    print(resp.text)
    return resp.text, resp.url + '&begin=20251003T100000&end=20251003T100100'

# === 2. Extract query parameters (hdnea token) ===
def extract_query_params(url):
    """
    Extract query parameters like ?hdnea=... from URL
    """
    parsed = urlparse(url)
    return parsed.query

# === 3. Add query params to segment URL ===
def add_token_to_url(segment_url, query_string):
    """
    Append hdnea token to segment URL
    """
    if not query_string:
        return segment_url
    
    # Check if segment URL already has query params
    separator = '&' if '?' in segment_url else '?'
    return f"{segment_url}{separator}{query_string}"

# === 4. Parse MPD and extract audio segment URL (PHP logic) ===
def get_first_segment_url(mpd_text, base_url, mpd_query_params, is_catchup=False):
    """
    Parse MPD to find the first audio segment URL
    Matches PHP extractWidevinePssh() logic exactly:
    - Looks for audio AdaptationSet
    - Calculates segment number based on catchup/live mode
    - Constructs URL as $baseUrl/dash/$media
    """
    ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}
    root = ET.fromstring(mpd_text)
    
    # Find Period -> AdaptationSet with contentType="audio"
    for period in root.findall('.//mpd:Period', ns):
        for aset in period.findall('.//mpd:AdaptationSet', ns):
            content_type = aset.get('contentType', '')
            
            # Look for audio only (matching PHP)
            if content_type == 'audio':
                print(f"[*] Found audio AdaptationSet")
                
                # Find first Representation
                for representation in aset.findall('.//mpd:Representation', ns):
                    rep_id = representation.get('id', '')
                    print(f"[*] Representation ID: {rep_id}")
                    
                    # Check for SegmentTemplate
                    seg_template = representation.find('.//mpd:SegmentTemplate', ns)
                    if seg_template is not None:
                        media_template = seg_template.get('media')
                        start_number_attr = seg_template.get('startNumber', '0')
                        start_number = int(start_number_attr)
                        
                        print(f"[*] Media template: {media_template}")
                        print(f"[*] Start number: {start_number}")
                        
                        # Calculate segment number based on catchup mode
                        # PHP: $startNumber = $catchupRequest ? (int)($template['startNumber'] ?? 0) : (int)($template['startNumber'] ?? 0) + (int)($template->SegmentTimeline->S['r'] ?? 0);
                        if is_catchup:
                            segment_number = start_number
                            print(f"[*] Catchup mode: using startNumber = {segment_number}")
                        else:
                            # For live, add SegmentTimeline->S['r']
                            r_value = 0
                            seg_timeline = seg_template.find('.//mpd:SegmentTimeline', ns)
                            if seg_timeline is not None:
                                s_elem = seg_timeline.find('.//mpd:S', ns)
                                if s_elem is not None:
                                    r_value = int(s_elem.get('r', '0'))
                            segment_number = start_number + r_value
                            print(f"[*] Live mode: startNumber({start_number}) + r({r_value}) = {segment_number}")
                        
                        if media_template:
                            # Replace template variables
                            # PHP: str_replace(['$RepresentationID$', '$Number$'], [(string)$rep['id'], $startNumber], $template['media'])
                            media = media_template.replace('$RepresentationID$', rep_id)
                            media = media.replace('$Number$', str(segment_number))
                            
                            # Construct URL: "$baseUrl/dash/$media"
                            # baseUrl is dirname of MPD URL
                            parsed = urlparse(base_url)
                            base_path = parsed.scheme + '://' + parsed.netloc
                            # Get directory path (dirname)
                            path_parts = parsed.path.rsplit('/', 1)
                            if len(path_parts) > 1:
                                base_path += path_parts[0]
                            
                            segment_url = f"{base_path}/dash/{media}"
                            
                            # Add hdnea token
                            segment_url = add_token_to_url(segment_url, mpd_query_params)
                            print(f"[+] Audio segment URL: {segment_url}")
                            return segment_url
    
    raise Exception("No audio segment URL found in MPD")

# === 5. Download segment binary ===
def fetch_segment(url):
    print(f"[*] Fetching segment: {url}...")
    resp = requests.get(url, headers=HEADERS)
    resp.raise_for_status()
    print(f"[+] Segment downloaded, size: {len(resp.content)} bytes")
    return resp.content

# === 6. Extract KID and PSSH from segment binary (exact PHP logic) ===
def extract_kid_pssh_from_segment(binary_content):
    """
    Extract KID from PSSH box in segment binary
    Matches PHP extractKid() function exactly
    """
    # Convert binary to hex string
    hex_content = binary_content.hex()
    
    # Find PSSH marker "70737368" = "pssh" in ASCII
    pssh_marker = "70737368"
    pssh_offset = hex_content.find(pssh_marker)
    
    if pssh_offset == -1:
        raise Exception("PSSH box not found in segment")
    
    print(f"[+] PSSH box found at hex offset: {pssh_offset}")
    
    # Extract size (4 bytes before "pssh")
    # PHP: substr($hexContent, $psshOffset - 8, 8)
    header_size_hex = hex_content[pssh_offset - 8:pssh_offset]
    header_size = int(header_size_hex, 16)
    print(f"[+] PSSH box size: {header_size} bytes (0x{header_size_hex})")
    
    # Extract full PSSH box
    # PHP: substr($hexContent, $psshOffset - 8, $headerSize * 2)
    pssh_hex = hex_content[pssh_offset - 8:pssh_offset - 8 + header_size * 2]
    
    # Extract KID at offset 68 (32 hex chars = 16 bytes)
    # PHP: substr($psshHex, 68, 32)
    kid_hex = pssh_hex[68:68 + 32]
    
    if len(kid_hex) != 32:
        raise Exception(f"Invalid KID length: {len(kid_hex)} (expected 32 hex chars)")
    
    print(f"[+] KID (hex): {kid_hex}")
    
    # Build new Widevine PSSH box
    # PHP: "000000327073736800000000edef8ba979d64acea3c827dcd51d21ed000000121210" . $kidHex
    new_pssh_hex = "000000327073736800000000edef8ba979d64acea3c827dcd51d21ed000000121210" + kid_hex
    
    # Convert hex to binary then base64
    # PHP: base64_encode(hex2bin($newPsshHex))
    pssh_binary = bytes.fromhex(new_pssh_hex)
    pssh_b64 = base64.b64encode(pssh_binary).decode('utf-8')
    
    # Format KID as UUID
    # PHP: substr($kidHex, 0, 8) . "-" . substr($kidHex, 8, 4) . "-" . substr($kidHex, 12, 4) . "-" . substr($kidHex, 16, 4) . "-" . substr($kidHex, 20)
    kid_uuid = f"{kid_hex[0:8]}-{kid_hex[8:12]}-{kid_hex[12:16]}-{kid_hex[16:20]}-{kid_hex[20:32]}"
    
    print(f"[+] KID (UUID): {kid_uuid}")
    print(f"[+] PSSH (base64): {pssh_b64}")
    
    return {
        'kid': kid_uuid,
        'kid_hex': kid_hex,
        'pssh': pssh_b64
    }

# === 7. Main extraction function ===
def extract_widevine_pssh(mpd_url):
    """
    Main function: fetch MPD → get segment → extract KID/PSSH
    Returns both DRM info and final MPD URL
    Matches PHP extractWidevinePssh() workflow
    """
    # Fetch MPD
    mpd_content, final_url = fetch_mpd(mpd_url)
    
    # Extract query parameters (hdnea token)
    query_params = extract_query_params(final_url)
    print(f"[*] Token params: {query_params[:50]}..." if len(query_params) > 50 else f"[*] Token params: {query_params}")
    
    # Determine if this is a catchup request
    is_catchup = True
    print(f"[*] Catchup mode: {is_catchup}")
    
    # Get first segment URL (audio, with token)
    segment_url = get_first_segment_url(mpd_content, final_url, query_params, is_catchup)
    
    # Download segment
    segment_binary = fetch_segment(segment_url)
    
    # Extract KID and PSSH
    result = extract_kid_pssh_from_segment(segment_binary)
    
    # Return DRM info and final MPD URL
    return result, final_url

# === 8. Get decryption keys ===
def get_keys(KID_UUID, license_url):
    """
    Use extracted KID to get keys from license server
    """
    print("\n[*] Starting Widevine key extraction...")
    import uuid, base64
    print(KID_UUID)
    raw_bytes = uuid.UUID(KID_UUID).bytes
    b64url_kid = base64.urlsafe_b64encode(raw_bytes).rstrip(b'=').decode()
    print(f"[*] KID (base64url): {b64url_kid}")
    
    # Prepare request payload
    payload = {
        "kids": [b64url_kid],
        "type": "temporary"
    }

    # Headers for license request
    license_headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0',
        **HEADERS  # Include other headers
    }

    print(f"[*] Requesting keys from: {license_url}")
    print(f"[*] Payload: {payload}")

    # Make license request
    response = requests.post(license_url, json=payload, headers=license_headers)
    response.raise_for_status()

    license_data = response.json()
    print(f"[*] License response: {license_data}")

    # Extract and convert keys
    keys = []
    if 'keys' in license_data:
        for key_data in license_data['keys']:
            if 'k' in key_data and 'kid' in key_data:
                # Decode base64 key and kid to hex
                key_b64 = key_data['k']
                kid_b64 = key_data['kid']
                
                # Add padding if needed and decode
                key_hex = base64.urlsafe_b64decode(key_b64 + '==').hex()
                kid_hex = base64.urlsafe_b64decode(kid_b64 + '==').hex()
                
                keys.append(f"{kid_hex}:{key_hex}")
                print(f"[+] Key: {kid_hex}:{key_hex}")
    else:
        print("[!] No keys found in license response")
    
    return keys

# === 9. Download content using yt-dlp ===
def download_with_ytdlp(mpd_url, output_path, format_id=None):
    """
    Download encrypted content using yt-dlp
    Allows downloading unplayable/encrypted formats
    """
    print(f"\n[*] Downloading content with yt-dlp...")
    print(f"[*] MPD URL: {mpd_url[:100]}...")
    print(f"[*] Output: {output_path}")
    
    # Build yt-dlp command
    cmd = [
        'yt-dlp',
        '--verbose',
        '--print-traffic',
        '--allow-unplayable-formats',
        '--add-header', f'Origin: {HEADERS["Origin"]}',
        '--add-header', f'Referer: {HEADERS["Referer"]}',
        '--add-header', f'User-Agent: {HEADERS["User-Agent"]}',
        '--add-header', f'X-User-Agent: {HEADERS["X-User-Agent"]}',
    ]
    
    if format_id:
        cmd.extend(['-f', format_id])
    
    cmd.extend([
        '-o', output_path,
        mpd_url
    ])
    
    print(f"[*] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        print(f"[+] Download completed: {output_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Download failed: {e}")
        print(f"[!] stdout: {e.stdout}")
        print(f"[!] stderr: {e.stderr}")
        return False

# === 10. Decrypt content using mp4decrypt ===
def decrypt_with_mp4decrypt(input_file, output_file, keys):
    """
    Decrypt content using mp4decrypt with extracted keys
    """
    print(f"\n[*] Decrypting with mp4decrypt...")
    print(f"[*] Input: {input_file}")
    print(f"[*] Output: {output_file}")
    
    if not os.path.exists(input_file):
        print(f"[!] Input file does not exist: {input_file}")
        return False
    
    # Build mp4decrypt command
    cmd = ['./mp4decrypt']
    
    # Add all keys
    for key in keys:
        cmd.extend(['--key', key])
    
    cmd.extend([input_file, output_file])
    
    print(f"[*] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
        print(f"[+] Decryption completed: {output_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Decryption failed: {e}")
        print(f"[!] stderr: {e.stderr}")
        return False

# === 11. Merge video and audio using ffmpeg ===
def merge_video_audio(video_file, audio_file, output_file):
    """
    Merge decrypted video and audio using ffmpeg
    """
    print(f"\n[*] Merging video and audio with ffmpeg...")
    print(f"[*] Video: {video_file}")
    print(f"[*] Audio: {audio_file}")
    print(f"[*] Output: {output_file}")
    
    cmd = [
        'ffmpeg',
        '-i', video_file,
        '-i', audio_file,
        '-c', 'copy',  # Copy without re-encoding
        '-y',  # Overwrite output file
        output_file
    ]
    
    print(f"[*] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
        print(f"[+] Merge completed: {output_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Merge failed: {e}")
        print(f"[!] stderr: {e.stderr}")
        return False

# === 12. List available formats ===
def list_formats(mpd_url):
    """
    List available formats using yt-dlp
    """
    print("\n[*] Listing available formats...")
    
    cmd = [
        'yt-dlp',
        '--verbose',
        '--print-traffic',
        '--allow-unplayable-formats',
        '--list-formats',
        '--add-header', f'Origin: {HEADERS["Origin"]}',
        '--add-header', f'Referer: {HEADERS["Referer"]}',
        '--add-header', f'User-Agent: {HEADERS["User-Agent"]}',
        '--add-header', f'X-User-Agent: {HEADERS["X-User-Agent"]}',
        mpd_url
    ]
    
    print(f"[*] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to list formats: {e}")
        print(f"[!] stdout: {e.stdout}")
        print(f"[!] stderr: {e.stderr}")
        return None

# === 13. Run everything ===
if __name__ == "__main__":
    try:
        # Create output directory
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # Step 1: Extract KID and PSSH from segment + get final MPD URL
        print("\n" + "="*60)
        print("STEP 1: EXTRACTING DRM INFO (PHP METHOD)")
        print("="*60)
        drm_info, final_mpd_url = extract_widevine_pssh(MPD_URL)
        
        print("\n" + "="*60)
        print("EXTRACTED DRM INFO:")
        print("="*60)
        print(f"KID (UUID):  {drm_info['kid']}")
        print(f"KID (HEX):   {drm_info['kid_hex']}")
        print(f"PSSH:        {drm_info['pssh']}")
        print(f"\nFinal MPD URL for downloading:")
        print(f"{final_mpd_url}")
        print("="*60)
        
        # Step 2: Get decryption keys
        print("\n" + "="*60)
        print("STEP 2: GETTING DECRYPTION KEYS")
        print("="*60)
        keys = get_keys(drm_info['kid'], LICENSE_URL)
        
        print("\n" + "="*60)
        print("DECRYPTION KEYS:")
        print("="*60)
        for key in keys:
            print(key)
        print("="*60)
        
        if not keys:
            print("[!] No keys obtained. Cannot proceed with download/decryption.")
            sys.exit(1)
        
        # Step 3: List available formats (optional)
        print("\n" + "="*60)
        print("STEP 3: LISTING AVAILABLE FORMATS")
        print("="*60)
        list_formats(final_mpd_url)
        
        # Step 4: Download encrypted content
        print("\n" + "="*60)
        print("STEP 4: DOWNLOADING ENCRYPTED CONTENT")
        print(f"Using Final MPD URL: {final_mpd_url}")
        print("="*60)
        
        # Download best video
        print("\n[*] Downloading best video...")
        video_success = download_with_ytdlp(
            final_mpd_url,
            ENCRYPTED_VIDEO,
            format_id='bv'  # best video
        )
        
        # Download best audio
        print("\n[*] Downloading best audio...")
        audio_success = download_with_ytdlp(
            final_mpd_url,
            ENCRYPTED_AUDIO,
            format_id='ba'  # best audio
        )
        
        if not video_success and not audio_success:
            print("[!] Download failed. Exiting.")
            sys.exit(1)
        
        # Step 5: Decrypt content
        print("\n" + "="*60)
        print("STEP 5: DECRYPTING CONTENT")
        print("="*60)
        
        # Decrypt video
        if video_success and os.path.exists(ENCRYPTED_VIDEO):
            print("\n[*] Decrypting video...")
            decrypt_with_mp4decrypt(ENCRYPTED_VIDEO, DECRYPTED_VIDEO, keys)
        
        # Decrypt audio
        if audio_success and os.path.exists(ENCRYPTED_AUDIO):
            print("\n[*] Decrypting audio...")
            decrypt_with_mp4decrypt(ENCRYPTED_AUDIO, DECRYPTED_AUDIO, keys)
        
        # Step 6: Merge video and audio
        print("\n" + "="*60)
        print("STEP 6: MERGING VIDEO AND AUDIO")
        print("="*60)
        
        if os.path.exists(DECRYPTED_VIDEO) and os.path.exists(DECRYPTED_AUDIO):
            merge_video_audio(DECRYPTED_VIDEO, DECRYPTED_AUDIO, FINAL_OUTPUT)
        elif os.path.exists(DECRYPTED_VIDEO):
            print("[*] Only video available, copying to final output...")
            import shutil
            shutil.copy(DECRYPTED_VIDEO, FINAL_OUTPUT)
        elif os.path.exists(DECRYPTED_AUDIO):
            print("[*] Only audio available, copying to final output...")
            import shutil
            shutil.copy(DECRYPTED_AUDIO, FINAL_OUTPUT)
        
        # Step 7: Cleanup (optional)
        print("\n" + "="*60)
        print("CLEANUP")
        print("="*60)
        print(f"[*] Encrypted files can be deleted:")
        print(f"    - {ENCRYPTED_VIDEO}")
        print(f"    - {ENCRYPTED_AUDIO}")
        print(f"[*] Final output: {FINAL_OUTPUT}")
        
        # Optionally delete encrypted files
        cleanup = input("\n[?] Delete encrypted files? (y/N): ").strip().lower()
        if cleanup == 'y':
            for file in [ENCRYPTED_VIDEO, ENCRYPTED_AUDIO]:
                if os.path.exists(file):
                    os.remove(file)
                    print(f"[+] Deleted: {file}")
        
        print("\n" + "="*60)
        print("PROCESS COMPLETED SUCCESSFULLY!")
        print("="*60)
        print(f"[+] Final output: {FINAL_OUTPUT}")
        
    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        import traceback
        traceback.print_exc()
