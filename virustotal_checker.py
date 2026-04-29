import requests
import base64

API_KEY = "fe62c59dd3434d7c94efa8a457aa0c7eeddfddd2650722aeb48d0bf1efac146a"

def check_virustotal(url):
    endpoint = f"https://www.virustotal.com/api/v3/urls"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(f"{endpoint}/{url_id}", headers=headers)
        data = response.json()
        for engine, result in data.get("data", {}).get("attributes", {}).get("last_analysis_results", {}).items():
            if result.get("category") == "malicious":
                return "malicious"
        return "safe"
    except:
        return "unknown"