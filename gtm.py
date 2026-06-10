import requests
import time

# User inputs the target Match ID (e.g., 1755642)
target_id = input("Enter Match ID: ")

url = "https://gaminglive.gaminghelperonline.com/api/coin-flip/current-match"

# Exact headers from your DevTools request
headers = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9,te;q=0.8,en-IN;q=0.7,hi;q=0.6",
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MjUzMDksImlhdCI6MTc4MTA4MDA2OCwiZXhwIjoxNzgzNjcyMDY4fQ.gwmvP1s1yyMHK32sWeG0Eg1F72tel4VyPbvqILOBWXQ", # Insert your actual token
    "Connection": "keep-alive",
    "DNT": "1",
    "Host": "gaminglive.gaminghelperonline.com",
    "Origin": "https://gaminghelperonline.com",
    "Referer": "https://gaminghelperonline.com/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode: "cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
}

print(f"Polling for Match {target_id}...")

while True:
    try:
        # Requesting without sleep for maximum speed (Warning: Risk of 429 Rate Limit)
        response = requests.get(url, headers=headers, timeout=5)
        data = response.json()
        
        match = data.get("currentMatch", {})
        
        # Verify if we are looking at the correct match
        if str(match.get("id")) == target_id:
            res = match.get("final_result")
            is_gen = match.get("winner_generated")
            
            if res and is_gen == 1:
                print(f"\n[SUCCESS] Match {target_id} Result: {res}")
                break
            else:
                print(f"Status: Live | Waiting for server to generate result...", end="\r")
        else:
            # If the ID is no longer 'currentMatch', check the first item in history
            past = data.get("pastResults", [])
            if past:
                print(f"\n[INFO] Match shifted to history. Latest result: {past[0].get('final_result')}")
                break
                
    except Exception as e:
        print(f"\n[ERROR] {e}")
        break

    # Smallest possible delay to avoid immediate Cloudflare IP ban
    time.sleep(0.5)
