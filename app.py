from flask import Flask, request, jsonify
from ai_connector import hybrid_decision

app = Flask("SecureScan")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "No URL"}), 400
    
    full_report = hybrid_decision(url)
    return jsonify(full_report)

if __name__ == "__main__":
    app.run(debug=True, port=5000)