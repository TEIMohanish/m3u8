import requests
import time

def get_coin_flip_result(target_match_id):
    url = "https://gaminglive.gaminghelperonline.com/api/coin-flip/current-match"
    
    # Headers derived from your network request
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MjUzMDksImlhdCI6MTc4MTA4MDA2OCwiZXhwIjoxNzgzNjcyMDY4fQ.gwmvP1s1yyMHK32sWeG0Eg1F72tel4VyPbvqILOBWXQ",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        "Origin": "https://gaminghelperonline.com",
        "Referer": "https://gaminghelperonline.com/"
    }

    print(f"Searching for Match ID: {target_match_id}...")

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # 1. Check if it is the active match
        current = data.get("currentMatch", {})
        if str(current.get("id")) == str(target_match_id):
            result = current.get("final_result")
            if not result or current.get("winner_generated") == 0:
                return "Match is still live. No result yet."
            return f"Match {target_match_id} Result: {result}"

        # 2. Check past results (Note: API history items lack IDs, checking latest)
        past_results = data.get("pastResults", [])
        if past_results:
            # Since past results don't show IDs, we return the most recent outcome
            latest = past_results[0].get("final_result")
            return f"Match concluded. Latest outcome in history: {latest}"
        
        return "Match ID not found in current state."

    except Exception as e:
        return f"Request failed: {e}"

if __name__ == "__main__":
    user_match_id = input("Enter the Match ID to check: ")
    print(get_coin_flip_result(user_match_id))
