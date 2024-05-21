from flask import Flask
import requests
import json
import csv

app = Flask(__name__)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/hello")
def hello_world2():
    return "<p>Hello, World-2!</p>"


@app.route("/scrap")
def my_scrapper():
    # TODO 1. read the cve number from csv file
    # TODO 2. read the cve number from xlsx file

    # Specify the CSV file path
    csv_file_path = "output.csv"

    with open(csv_file_path, newline='') as csvfile:
        csv_content = csv.reader(csvfile)
        next(csv_content)   # Skip the first line in the following for loop
        for row in csv_content:
            print(row)
            cve_id = row[0]
            print(cve_id)
            response = requests.get(f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
            response_json = json.loads(response.text)
            cve_severity = response_json.get("threat_severity")
            print(f"severity = {cve_severity}")
            cvss3 = response_json.get("cvss3")
            cvss3_vector = cvss3.get("cvss3_scoring_vector")
            print(f"cvss v3 vector = {cvss3_vector}")




    cve_id = "CVE-2023-45802"
    response = requests.get(f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
    response_json = json.loads(response.text)
#    print(f"RESPONSE: {response_json}")
    cve_severity = response_json.get("threat_severity")
#    cve_severity = response_json[0].get("resource_url")
    cvss3 = response_json.get("cvss3")
    cvss3_vector = cvss3.get("cvss3_scoring_vector")
    print(f"severity = {cve_severity}")
    print(f"cvss v3 vector = {cvss3_vector}")
    # Specify the CSV file path
#    csv_file_path = "output.csv"

    # Write the value of field "CVE Severity" to the CSV file
    with open(csv_file_path, "w", newline="") as csvfile:
        fieldnames = ["CVE ID", "CVE Severity", "CVSS v3 Vector"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerow({"CVE ID": cve_id, "CVE Severity": cve_severity, "CVSS v3 Vector": cvss3_vector})


#    with open('request_info.md', 'w', encoding="utf-8") as f:
#        f.write(str(response.text))
    return response.text








if __name__ == '__main__':
    app.run(debug=True)


