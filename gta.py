import requests
import time

def monitor_and_trigger_winner(target_match_id):
    base_url = "https://gaminglive.gaminghelperonline.com/api"
    current_match_url = f"{base_url}/coin-flip/current-match"
    create_winner_url = f"{base_url}/coin-flip/create-winner"
    
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MjUzMDksImlhdCI6MTc4MTE2MDMwOSwiZXhwIjoxNzgzNzUyMzA5fQ.uiVaADu8-cMatEThn22yrOB4y3R3xQoX1XMENzKsu6Y",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        "Origin": "https://gaminghelperonline.com",
        "Referer": "https://gaminghelperonline.com/"
    }

    print(f"Monitoring Match ID: {target_match_id}...")

    while True:
        try:
            # 1. Check current status
            response = requests.get(current_match_url, headers=headers)
            response.raise_for_status()
            data = response.json()
            current = data.get("currentMatch", {})

            # 2. If it's our target match and result is missing, try to create it
            if str(current.get("id")) == str(target_match_id):
                final_res = current.get("final_result")
                
                if final_res:
                    print(f"\n[!] MATCH {target_match_id} FINISHED: {final_res}")
                    break
                else:
                    # IMPLEMENTATION: Request the backend to generate the winner
                    print(f"\rMatch {target_match_id} live. Sending create-winner request...", end="")
                    requests.post(create_winner_url, headers=headers)
            
            else:
                print(f"\n[!] Match ID {target_match_id} is no longer current.")
                break

        except Exception as e:
            print(f"\n[!] Error: {e}")
            break
        
        time.sleep(3) # Check every 3 seconds

if __name__ == "__main__":
    match_id = input("Enter Match ID: ")
    monitor_and_trigger_winner(match_id)
