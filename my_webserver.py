from flask import Flask
import configparser
import requests
import json
import csv
import logging
import datetime
import os
import pandas as pd


app = Flask(__name__)

# Set the log level
app.logger.setLevel(logging.INFO)

# Define a file handler and set its format
file_handler = logging.FileHandler('flask.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Add the file handler to the app's logger
app.logger.addHandler(file_handler)

product = "NCS"
# TODO Read product information from the excel file


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/hello")
def hello_world2():
    return "<p>Hello, World-2!</p>"


@app.route("/scrap")
def my_scrapper():
    # TODO Replace all constants with the config variable
    
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

    df = pd.read_excel(last_file, header = 3)
    app.logger.info(f'{df}')

    # Extract CVE IDs from the excel file
    # Check if 'CVE ID' column exists in the DataFrame
    if 'CVE ID' in df.columns:
        # Extract the data from the 'CVE ID' column into a list
        cve_list = df['CVE ID'].dropna().tolist()
        print(cve_list)
        app.logger.info(f'The CVE IDs extracted from the Excel file are: {cve_list}')
    else:
        print("The 'CVE ID' column does not exist in the Excel file.")
        app.logger.error(f'The "CVE ID" column does not exist in the Excel file {last_file}.')
    
    # Extract Disposition Rationale field from the excel file
    # Check if 'Disposition Rationale' column exists in the DataFrame
    if 'Disposition Rationale' in df.columns:
        # Extract the data from the 'Disposition Rationale' column into a string
        disposition_rationale = df['Disposition Rationale'].dropna().tolist()
        print(disposition_rationale)
        app.logger.info(f'The Disposition Rationale extracted from the Excel file is: {disposition_rationale}')
    else:
        print("The 'Disposition Rationale' column does not exist in the Excel file.")
        app.logger.error(f'The "Disposition Rationale" column does not exist in the Excel file {last_file}.')
    




    with open(first_file, newline='') as csvfile:
        csv_content = csv.reader(csvfile)
        next(csv_content)   # Skip the first line (the header line) in the following 'for' loop
        cve_list = []
        for row in csv_content:
            app.logger.info(f'Row: {row}')
            cve_list.append(row[0])
            app.logger.info(f'CVE list: {cve_list}')

    # Create a csv output filename with a timestamp prefix
    output_csv_filename = create_output_filename(first_file)

    # Create an xlsx output filename with a timestamp prefix
    output_xls_filename = create_output_filename(last_file)

    # Create the header row
    header = config.get('CVE_INPUT', 'HEADER_FIELD_NAMES')
    header = header.split(',')
    app.logger.info(f'Header is: {header}')

    rows = []

    with open(output_csv_filename, "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
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
            disposition_rationale = ""
            disposition_rationale = disposition_rationale + add_rationale_from_cvss3(cvss3_vector)
            writer.writerow({"CVE ID": cve_id, "CVE Severity": cve_severity, "CVSS v3 Vector": cvss3_vector, "Disposition Rationale": disposition_rationale})
            next_row = [cve_id, cve_severity, cvss3_vector, disposition_rationale]
            rows.append(next_row)
            app.logger.info(f'Rows are: {rows}')

    # Create a new DataFrame with the header and rows
    df_new = pd.DataFrame(rows, columns=header)

    # Save the updated DataFrame back to the Excel file
    df_new.to_excel(output_xls_filename, index=False, startrow=0, startcol=0)


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


def add_rationale_from_cvss3(cvss3_vector):
    app.logger.info(f'Adding text to the Disposition Rationale field based on the CVSS v3 Vector: {cvss3_vector}')


    # Split the CVSS v3 vector string by '/'
    metrics = cvss3_vector.split('/')
    
    # Initialize an empty list to hold the metrics as dictionaries
    dict_of_metrics = {}
    
    # Iterate over each metric
    for metric in metrics:
        # Split each metric by ':' into a metric name and a value pair
        metric_value_pairs = metric.split(':')
        
        # Ensure we have pairs of metric name and value
        if len(metric_value_pairs) == 2:
            metric_name, metric_value = metric_value_pairs
            # Add the new metric name - metric value pair to the dictionary
            dict_of_metrics[metric_name] = metric_value
        else:
            print(f"Skipping invalid element: {metric}")

    rationale_text_to_add = ""

    if dict_of_metrics["AV"] == "L":
        rationale_text_to_add = f"To exploit this vulnerability an attacker requires local access.\n" + f"Mitigated because {product} users are authenticated, audited and trusted."
    elif dict_of_metrics["AV"] == "P":
        rationale_text_to_add = f"To exploit this vulnerability an attacker requires physical access.\n" + f"Mitigated because {product} users are authenticated, audited and trusted."
    
    return rationale_text_to_add

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



# # defaultdict
#     id_to_cvelist = defaultdict(list)
#     for idx, entry in enumerate(cve_list):
#         id_to_cvelist[ids[idx]] = entry.split(',')
#     print(id_to_cvelist)

#     print(f'Existing key = {id_to_cvelist["id2"]}, non-existing key = {id_to_cvelist["id3"]}')

#     # dict comprehension
#     new_dict = {id: cve_entry.split(',') for id, cve_entry in zip(ids, cve_list)}
#     print(new_dict)


if __name__ == '__main__':
    app.run(debug=True)


