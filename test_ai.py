import requests

test_groups = {
    "🛡️ WHITELISTED": [
        "https://www.facebook.com",
        "https://www.github.com",
        "https://tripadvisor.com"
    ],
    "🎣 PHISHING": [
        "http://wellsfargo.com-verification-login.info",
        "http://secure-paypal-login.apple-support.net"
    ],
    "⚠️ TECHNICAL": [
        "http://103.21.244.0/admin/shell.php",
        "http://ama-zone-security-update.com/login",
        "https://tinyurl.com/2p9d4x7a",
        "https://cutt.ly/testlink",
         "https://rebrand.ly/example.txt",
         "https://hfhgbjyihnioj.com",
         "https://gftdg4.org"
         ,"https://Go0gle.com"
         ,"https://yghdtr.com"

    ]
}

print("=" * 80)
print("🚀 SafeScan AI FINAL TEST")
print("=" * 80)

for group_name, urls in test_groups.items():
    print(f"\n{group_name}")
    print("-" * 50)

    for url in urls:
        try:
            response = requests.post(
                "http://127.0.0.1:5000/scan",
                json={"url": url}
            )

            res = response.json()

            score = res.get("score", 0)
            verdict = res.get("final_verdict", "Unknown")

            if verdict == "Safe":
                icon = "🟢 SAFE"
            elif verdict == "Potential Risk":
                icon = "🟡 POTENTIAL RISK"
            else:
                icon = "🔴 MALICIOUS"

            details = res.get("details", {})

            https_status = details["HTTPS"]["uses_https"]
            blacklist = details["Blacklist"]["blacklisted"]

            redirects = details["Redirects"]["redirect_count"]
            final_url = details["Redirects"]["final_url"]

            print(f"\n[>] URL        : {url}")
            print(f"    Score      : {score}%")
            print(f"    Verdict    : {icon}")
            print(f"    HTTPS      : {https_status}")
            print(f"    Redirects  : {redirects}")
            print(f"    Blacklist  : {blacklist}")
            print(f"    Final URL  : {final_url}")
            print("." * 60)

        except Exception as e:
            print("Error:", e)

print("=" * 80)
print("✅ ALL TESTS DONE")
print("=" * 80)