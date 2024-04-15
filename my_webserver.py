from flask import Flask
import requests

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/hello")
def hello_world2():
    return "<p>Hello, World-2!</p>"

@app.route("/scrapper")
def my_scrapper():
    web_page = requests.get("https://access.redhat.com/security/cve/CVE-2023-45803")
    return web_page.content
