import requests
import time

def monitor_match(target_match_id):
    url = "https://gaminglive.gaminghelperonline.com/api/coin-flip/current-match"
    
    # Headers from your request
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MjUzMDksImlhdCI6MTc4MTA4MDA2OCwiZXhwIjoxNzgzNjcyMDY4fQ.gwmvP1s1yyMHK32sWeG0Eg1F72tel4VyPbvqILOBWXQ", # Insert your actual token
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        "Origin": "https://gaminghelperonline.com",
        "Referer": "https://gaminghelperonline.com/"
    }

    print(f"Monitoring Match ID: {target_match_id}. Waiting for result...")

    while True:
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            current = data.get("currentMatch", {})

            # Check if the match is still the one we are watching
            if str(current.get("id")) == str(target_match_id):
                final_res = current.get("final_result")
                
                if final_res: # Result has been populated
                    print(f"\n[!] MATCH {target_match_id} FINISHED: {final_res}")
                    break
                else:
                    print(f"Match {target_match_id} is still live... checking again in 5s.", end="\r")
            
            else:
                # If the ID changed, the target match moved to 'pastResults'
                for past in data.get("pastResults", []):
                    # Note: API doesn't show ID in pastResults, so we assume the first one 
                    # is the match that just finished.
                    print(f"\n[!] Match ID changed. Newest result in history: {past.get('final_result')}")
                    return

        except Exception as e:
            print(f"\n[!] Error: {e}")
            break
        
        time.sleep(5) # Poll every 5 seconds to avoid rate limiting

if __name__ == "__main__":
    match_id = input("Enter the Match ID to watch for a result: ")
    monitor_match(match_id)
