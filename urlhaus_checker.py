import requests

def check_urlhaus(url):
    try:
        response = requests.get(f"https://urlhaus.abuse.ch/api/v1/url/{url}/")
        data = response.json()
        if data.get("query_status") == "ok":
            return "malicious"
        else:
            return "safe"
    except:
        return "unknown"