from flask import Flask
import configparser
import requests
import json
import csv
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
    # TODO 2. read the cve number from xlsx file

    config = load_config()
    csv_file_path = config.get('CVE', 'CVE_FILE_NAME')
    cve_list = []
    
    with open(csv_file_path, newline='') as csvfile:
        csv_content = csv.reader(csvfile)
        next(csv_content)   # Skip the first line in the following 'for' loop
        for row in csv_content:
            app.logger.info('Row: ' + str(row))
            cve_list.append(row[0])
            app.logger.info('CVE list: ' + str(cve_list))

    # TODO Replace all constants with the config variable
    # TODO search for the xlsx file

#    cve_list = config.get('CVE', 'CVE_LIST')
#    app.logger.info('CVE list to be parsed: ' + cve_list)
#    cve_list = cve_list.split(',')
#    app.logger.info('CVE list represented as list of strings: ' + str(cve_list))
    csv_file_path = 'Output_'+csv_file_path
    with open(csv_file_path, "a", newline="") as csvfile:
        fieldnames = config.get('CVE', 'HEADER_FIELD_NAMES')
        fieldnames = fieldnames.split(',')
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for cve_id in cve_list:
            app.logger.info('CVE to be processed: ' + cve_id)
            response = requests.get(f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
            response_json = json.loads(response.text)
            cve_severity = response_json.get("threat_severity")
            app.logger.info('Severity: ' + cve_severity)
            cvss3 = response_json.get("cvss3")
            cvss3_vector = cvss3.get("cvss3_scoring_vector")
            app.logger.info('CVSS v3 Vector: ' + cvss3_vector)
            writer.writerow({"CVE ID": cve_id, "CVE Severity": cve_severity, "CVSS v3 Vector": cvss3_vector})


#    with open('request_info.md', 'w', encoding="utf-8") as f:
#        f.write(str(response.text))
    return response.text



def load_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config







if __name__ == '__main__':
    app.run(debug=True)


