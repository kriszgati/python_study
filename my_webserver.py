from flask import Flask
import configparser
import requests
import json
import csv
import logging
import datetime
import os


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
    # TODO Replace all constants with the config variable
    # TODO Search for the input file
    # TODO Add an entry point log
    # TODO Add the timestamp to the output file name
    # TODO Use xlsx file instead of csv file

    app.logger.info(f'*******************************')
    app.logger.info(f'**  The scrapper is running  **')
    app.logger.info(f'*******************************')

    config = load_config()
    input_file_name_pattern = config.get('CVE_INPUT', 'FILE_PREFIX')
    directory = config.get('CVE_INPUT', 'SEARCH_PATH')
    cve_list = []

    matches = find_files(directory, input_file_name_pattern)
    app.logger.info(f'The following files are found: {matches}')
    last_file = matches[-1]
    app.logger.info(f'The last file in the list is: {last_file}')
    first_file = matches[0]
    app.logger.info(f'The first file in the list is: {first_file}')
    
    with open(first_file, newline='') as csvfile:
        csv_content = csv.reader(csvfile)
        next(csv_content)   # Skip the first line (the header line) in the following 'for' loop
        for row in csv_content:
            app.logger.info(f'Row: {row}')
            cve_list.append(row[0])
            app.logger.info(f'CVE list: {cve_list}')

    # Create the output filename with a timestamp prefix
    output_filename = create_output_filename(first_file)

    with open(output_filename, "a", newline="") as csvfile:
        fieldnames = config.get('CVE_INPUT', 'HEADER_FIELD_NAMES')
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


# Function to search for files that start with a given pattern in a directory
def find_files(directory, pattern):
    app.logger.info(f'Searching for files in the {directory} directory, starting with the following pattern: {pattern}')
    matches = []
    app.logger.info(f'The following files are found:')
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.startswith(pattern):
                app.logger.info(filename)
                matches.append(os.path.join(root, filename))
    return matches


# Function to create an output filename with a timestamp prefix
def create_output_filename(input_filename):
    app.logger.info(f'Creating file name from the current time and the input file name')
    current_time = datetime.datetime.now()
    app.logger.info(f'The current time is: {current_time}')
    timestamp = current_time.strftime("%Y-%m-%d_%H-%M-%S")
    app.logger.info(f'The timestamp is: {timestamp}')
    directory, filename = os.path.split(input_filename)
    output_filename = f"{timestamp}_{filename}"
    app.logger.info(f'The output file name is: {output_filename}')
    return os.path.join(directory, output_filename)



if __name__ == '__main__':
    app.run(debug=True)


