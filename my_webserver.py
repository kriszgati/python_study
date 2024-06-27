from flask import Flask
import configparser
import requests
import json
import math
import logging
import datetime
import os
import pandas as pd


app = Flask(__name__)

# Set the log level
app.logger.setLevel(logging.INFO)

# Define a file handler for the log file and set its format
file_handler = logging.FileHandler('flask.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Add the file handler to the app's logger
app.logger.addHandler(file_handler)

product = "NCS"
# TODO Read product information from the excel file


@app.route("/scrap")
def my_scrapper():
    app.logger.info(f'*******************************')
    app.logger.info(f'**  The scrapper is running  **')
    app.logger.info(f'*******************************')

    config = load_config()
    input_file_name_pattern = config.get('CVE_INPUT', 'FILE_PREFIX')
    directory = config.get('CVE_INPUT', 'SEARCH_PATH')
    cve_ids = []

    matches = find_files(directory, input_file_name_pattern)
    app.logger.info(f'The following files are found: {matches}')
    last_file = matches[-1]
    app.logger.info(f'The last file in the list is: {last_file}')
#    first_file = matches[0]
#    app.logger.info(f'The first file in the list is: {first_file}')

    # Read the excel file into a DataFrame, starting from row 4
    df = pd.read_excel(last_file, header = 3)
    app.logger.info(f'{df}')

    # Extract product information from the excel file
    # Check if 'Product' column exists in the DataFrame
    if 'Product' in df.columns:
        # Extract the data from the 'Product' column into a list
        products = df['Product'].tolist()
        app.logger.info(f'The Products extracted from the Excel file are: {products}')
    else:
        app.logger.error(f'The "Product" column does not exist in the Excel file {last_file}.')
    
    # Extract release information from the excel file
    # Check if 'Release' column exists in the DataFrame
    if 'Release' in df.columns:
        # Extract the data from the 'Release' column into a list
        releases = df['Release'].tolist()
        app.logger.info(f'The Releases extracted from the Excel file are: {releases}')
    else:
        app.logger.error(f'The "Release" column does not exist in the Excel file {last_file}.')
    
    # Extract CVE IDs from the excel file
    # Check if 'CVE ID' column exists in the DataFrame
    if 'CVE ID' in df.columns:
        # Extract the data from the 'CVE ID' column into a list
        cve_ids = df['CVE ID'].tolist()
        app.logger.info(f'The CVE IDs extracted from the Excel file are: {cve_ids}')
    else:
        app.logger.error(f'The "CVE ID" column does not exist in the Excel file {last_file}.')
    
    # Extract Disposition Rationale column from the excel file
    # Check if 'Disposition Rationale' column exists in the DataFrame
    if 'Disposition Rationale' in df.columns:
        # Extract the data from the 'Disposition Rationale' column into a string
        disposition_rationales = df['Disposition Rationale'].tolist()
        app.logger.info(f'The Disposition Rationale fields extracted from the Excel file are: {disposition_rationales}')
    else:
        app.logger.error(f'The "Disposition Rationale" column does not exist in the Excel file {last_file}.')
    
    # Extract Internal Comments (optional) column from the excel file
    # Check if 'Internal Comments (optional)' column exists in the DataFrame
    if 'Internal Comments (optional)' in df.columns:
        # Extract the data from the 'Internal Comments (optional)' column into a string
        internal_comments_list = df['Internal Comments (optional)'].tolist()
        app.logger.info(f'The Internal Comments (optional) fields extracted from the Excel file are: {internal_comments_list}')
    else:
        app.logger.error(f'The "Internal Comments (optional)" column does not exist in the Excel file {last_file}.')
    
    # Extract Mitigation Tool:Tracking ID column from the excel file
    # Check if 'Mitigation Tool:Tracking ID' column exists in the DataFrame
    if 'Mitigation Tool:Tracking ID' in df.columns:
        # Extract the data from the 'Mitigation Tool:Tracking ID' column into a string
        tracking_ids_list = df['Mitigation Tool:Tracking ID'].tolist()
        app.logger.info(f'The Mitigation Tool:Tracking ID fields extracted from the Excel file are: {tracking_ids_list}')
    else:
        app.logger.error(f'The "Mitigation Tool:Tracking ID" column does not exist in the Excel file {last_file}.')

    # Create an xlsx output filename with a timestamp prefix
#    output_xls_filename = create_output_filename(last_file)

    for cve_id in cve_ids:
        if (isinstance(cve_id, float) and math.isnan(cve_id)) or cve_id == None:
            continue
        app.logger.info(f'CVE to be processed: {cve_id}')
        response = requests.get(f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
        response_json = json.loads(response.text)
        cve_severity = response_json.get("threat_severity")
        app.logger.info('Severity: ' + cve_severity)
        cvss3 = response_json.get("cvss3")
        cvss3_vector = cvss3.get("cvss3_scoring_vector")
        app.logger.info(f'CVSS v3 Vector: {cvss3_vector}')
        disposition_rationale = ""
        disposition_rationale = disposition_rationale + add_rationale_from_cvss3(cvss3_vector)
#        writer.writerow({"CVE ID": cve_id, "CVE Severity": cve_severity, "CVSS v3 Vector": cvss3_vector, "Disposition Rationale": disposition_rationale})
#        next_row = [cve_id, cve_severity, cvss3_vector, disposition_rationale]
#        rows.append(next_row)
#        app.logger.info(f'Rows are: {rows}')

    # Create a new DataFrame with the header and rows
#    df_new = pd.DataFrame(rows, columns=header)

    # Save the updated DataFrame back to the Excel file
#    df_new.to_excel(output_xls_filename, index=False, startrow=0, startcol=0)

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
#     for idx, entry in enumerate(cve_ids):
#         id_to_cvelist[ids[idx]] = entry.split(',')
#     print(id_to_cvelist)

#     print(f'Existing key = {id_to_cvelist["id2"]}, non-existing key = {id_to_cvelist["id3"]}')

#     # dict comprehension
#     new_dict = {id: cve_entry.split(',') for id, cve_entry in zip(ids, cve_ids)}
#     print(new_dict)


if __name__ == '__main__':
    app.run(debug=True)


