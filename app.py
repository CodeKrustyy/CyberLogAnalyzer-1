from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "Cyber Log Analyzer is Running!"

if __name__ == '__main__':
    app.run(debug=True)
