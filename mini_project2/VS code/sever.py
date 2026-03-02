# server.py
from flask import Flask, request, render_template_string, jsonify
from base64 import b64decode
from Crypto.Cipher import AES
import requests

app = Flask(__name__)
ESP32_BASE = "http://172.20.10.3"  # change if your ESP32 IP changes

# In-memory storage for team data
team_data = {}

# ========= MUST MATCH ESP32 KEY/IV =========
AES_KEY = b"0123456789ABCDEF"  # 16 bytes (AES-128)
AES_IV  = b"ABCDEF0123456789"  # 16 bytes (CBC IV)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Bad padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Bad padding")
    return data[:-pad_len]

def decrypt_payload_b64(payload_b64: str) -> dict:
    ct = b64decode(payload_b64)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    pt_padded = cipher.decrypt(ct)
    pt = pkcs7_unpad(pt_padded)
    # pt is JSON string bytes
    import json
    return json.loads(pt.decode("utf-8"))

@app.route('/')
def index():
    sorted_team_data = dict(sorted(team_data.items(), key=lambda item: int(item[0])))
    return render_template_string('''
        <!doctype html>
        <html>
        <head>
            <title>ESP32 Sensor Readings</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; }
                table { margin-left: auto; margin-right: auto; border-collapse: collapse; }
                th, td { border: 1px solid #ddd; padding: 8px; }
                th { background-color: #007bff; color: white; }
                tr:nth-child(even){background-color: #f2f2f2;}
                tr:hover {background-color: #ddd;}
            </style>
            <script>
                setTimeout(function(){ location.reload(); }, 5000);
            </script>
        </head>
        <body>
  <h1>ESP32 Sensor Readings</h1>

  <form action="/toggle-encryption" method="post" style="margin: 15px 0;">
    <button name="mode" value="on" type="submit">Enable Encryption</button>
    <button name="mode" value="off" type="submit">Disable Encryption</button>
  </form>

  <table>
    <tr>
      <th>Team #</th>
      <th>Temperature</th>
      <th>Humidity</th>
      <th>Timestamp</th>
      <th>Encrypted?</th>
      <th>Post Count</th>
    </tr>
    {% for team, data in sorted_team_data.items() %}
      <tr>
        <td>{{ team }}</td>
        <td>{{ data.temperature }}°C</td>
        <td>{{ data.humidity }}%</td>
        <td>{{ data.timestamp }}</td>
        <td>{{ data.encrypted }}</td>
        <td>{{ data.count }}</td>
      </tr>
    {% endfor %}
  </table>
</body>
   

        </html>
    ''', sorted_team_data=sorted_team_data)

@app.route('/post-data', methods=['POST'])
def receive_data():
    """
    Accepts:
      1) Plain JSON:
         { "team_number":"1", "temperature":..., "humidity":..., "timestamp":"..." }

      2) Encrypted JSON wrapper:
         { "team_number":"1", "encrypted":true, "payload_b64":"..." }
         where payload_b64 decrypts to:
         { "temperature":..., "humidity":..., "timestamp":"..." }
    """
    # Prefer JSON (project requirement)
    if request.is_json:
        data = request.get_json()
        print("RAW JSON RECEIVED:", data)
    else:
        # fallback: old form style
        data = request.form.to_dict()

    team_number = str(data.get("team_number", "0"))

    encrypted_flag = bool(data.get("encrypted", False))

    try:
        if encrypted_flag:
            decrypted = decrypt_payload_b64(data["payload_b64"])
            temperature = decrypted["temperature"]
            humidity = decrypted["humidity"]
            timestamp = decrypted["timestamp"]
            encrypted_text = "yes"
        else:
            temperature = data["temperature"]
            humidity = data["humidity"]
            timestamp = data["timestamp"]
            encrypted_text = "no"
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    if team_number not in team_data:
        team_data[team_number] = {
            "temperature": temperature,
            "humidity": humidity,
            "timestamp": timestamp,
            "encrypted": encrypted_text,
            "count": 1
        }
    else:
        team_data[team_number]["temperature"] = temperature
        team_data[team_number]["humidity"] = humidity
        team_data[team_number]["timestamp"] = timestamp
        team_data[team_number]["encrypted"] = encrypted_text
        team_data[team_number]["count"] += 1

    print(f"POST from team {team_number} | T={temperature} H={humidity} ts={timestamp} enc={encrypted_text}")
    return jsonify({"ok": True})
@app.route("/toggle-encryption", methods=["POST"])
def toggle_encryption():
    mode = request.form.get("mode", "on")  # on or off
    enc = "true" if mode == "on" else "false"

    try:
        # Use POST JSON because your ESP32 /config expects POST
        r = requests.post(
            f"{ESP32_BASE}/config",
            headers={"Content-Type": "application/json"},
            json={"encryption": (mode == "on")},
            timeout=3
        )
        # Return ESP32 response (may be plain text)
        try:
            return jsonify(r.json())
        except Exception:
            return jsonify({"ok": True, "esp32_response": r.text})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)

    