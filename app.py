from flask import Flask, render_template_string
from datetime import datetime, timedelta
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

@app.route('/')
def home():
    data = []
    failed_attempts = {}

    with open('logs.txt', 'r') as f:
        for line in f:
            timestamp_str, action, user_part = line.strip().split(" - ")
            user = user_part.split("user: ")[1]

            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            data.append([timestamp, action, user])

            if action == "LOGIN FAILED":
                if user not in failed_attempts:
                    failed_attempts[user] = []
                failed_attempts[user].append(timestamp)

    # =============================
    # 🔥 Time Window Detection
    # =============================
    suspicious_users = []

    for user, times in failed_attempts.items():
        times.sort()
        for i in range(len(times) - 2):
            if times[i+2] - times[i] <= timedelta(minutes=2):
                suspicious_users.append(user)
                break

    # =============================
    # 📊 Pandas + Graph
    # =============================
    df = pd.DataFrame(data, columns=["timestamp", "action", "user"])

    failed_counts = df[df["action"] == "LOGIN FAILED"]["user"].value_counts()

    plt.figure()
    failed_counts.plot(kind="bar")
    plt.title("Failed Login Attempts Per User")

    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)

    graph_url = base64.b64encode(img.getvalue()).decode()

    # =============================
    # 🤖 Machine Learning
    # =============================
    ml_suspicious = []

    X = []
    y = []

    for user, count in failed_counts.items():
        X.append([count])
        y.append(1 if count >= 3 else 0)

    if len(X) > 0:
        model = RandomForestClassifier()
        model.fit(X, y)

        predictions = model.predict(X)

        for i, user in enumerate(failed_counts.index):
            if predictions[i] == 1:
                ml_suspicious.append(user)

    # =============================
    # 🌐 HTML Output
    # =============================
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Log Analyzer</title>
    <style>
        body {{
            background-color: #0f172a;
            color: #e2e8f0;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }}

        h1 {{
            color: #38bdf8;
            text-align: center;
        }}

        .card {{
            background-color: #1e293b;
            padding: 20px;
            margin: 20px auto;
            border-radius: 12px;
            width: 80%;
            box-shadow: 0 0 20px rgba(0, 255, 150, 0.2);
        }}

        .alert {{
            color: #ef4444;
            font-weight: bold;
        }}

        .safe {{
            color: #22c55e;
            font-weight: bold;
        }}

        img {{
            display: block;
            margin: 0 auto;
            max-width: 100%;
        }}
    </style>
</head>
<body>

<h1>🛡 Cyber Log Analyzer Dashboard</h1>

<div class="card">
    <h2>🚨 Brute Force Detection</h2>
"""

    if suspicious_users:
        html += "<ul>"
        for user in suspicious_users:
            html += f"<li class='alert'>{user}</li>"
        html += "</ul>"
    else:
        html += "<p class='safe'>No brute force attacks detected.</p>"

    html += """
</div>

<div class="card">
    <h2>📊 Failed Login Graph</h2>
"""
    html += f'<img src="data:image/png;base64,{graph_url}">'

    html += """
</div>

<div class="card">
    <h2>🤖 Machine Learning Detection</h2>
"""

    if ml_suspicious:
        html += "<ul>"
        for user in ml_suspicious:
            html += f"<li class='alert'>{user} predicted as suspicious</li>"
        html += "</ul>"
    else:
        html += "<p class='safe'>No suspicious users predicted by ML.</p>"

    html += """
</div>

</body>
</html>
"""

    return render_template_string(html)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

