import subprocess

from flask import Flask


app = Flask(__name__)


@app.get("/health")
def health_check():
    result = subprocess.run(
        ["echo", "healthy"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
