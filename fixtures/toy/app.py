import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')
    # VULNERABLE: User input directly interpolated into shell command
    output = subprocess.run(f"ping -c 1 {ip}", shell=True, capture_output=True, text=True)
    return output.stdout

if __name__ == '__main__':
    app.run(port=5000)
