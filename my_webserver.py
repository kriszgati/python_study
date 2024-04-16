from flask import Flask
import requests
from bs4 import BeautifulSoup
import logging

app = Flask(__name__)

# Set the log level
app.logger.setLevel(logging.INFO)

# Define a file handler and set its format
file_handler = logging.FileHandler('flask.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Add the file handler to the app's logger
app.logger.addHandler(file_handler)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/hello")
def hello_world2():
    return "<p>Hello, World-2!</p>"

@app.route("/scrap")
def my_scrapper():
    response = requests.get("https://access.redhat.com/security/cve/CVE-2023-45803")
    soup = BeautifulSoup(response.text, 'html.parser')
    app.logger.error(soup)
    #with open('request_info.md', 'w') as f:
    #    f.write(str(response.text))
    return response.text

if __name__ == '__main__':
    app.run(debug=True)


