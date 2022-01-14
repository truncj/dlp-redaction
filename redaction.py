# Import the client library
import json
import os
import argparse

import google.cloud.dlp

from pathlib import Path
from tqdm import tqdm

parser = argparse.ArgumentParser()
parser.add_argument('--path', type=str, required=True, help='Path to input file')
parser.add_argument('--project-id', type=str, dest='project_id', required=True, help='GCP project id')
parser.add_argument('--token', type=str, required=True, help='GCP service account token')
parser.add_argument('--request-type', type=str, dest='request_type', required=True, help='inspect or deidentify')
args = parser.parse_args()

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = args.token

input_path = args.path
output_file = Path(input_path).stem
request_type = args.request_type

dc_file = open('configs/deidentify_config.json')
deidentify_config = json.load(dc_file)

# Instantiate a client.
dlp_client = google.cloud.dlp_v2.DlpServiceClient()
# The info types to search for in the content. Required.
info_types = [{"name": "FIRST_NAME"}, {"name": "LAST_NAME"}]
# The minimum likelihood to constitute a match. Optional.
min_likelihood = google.cloud.dlp_v2.Likelihood.LIKELIHOOD_UNSPECIFIED
# The maximum number of findings to report (0 = server maximum). Optional.
max_findings = 0
# Whether to include the matching string in the results. Optional.
include_quote = True

# Construct the configuration dictionary. Keys which are None may
# optionally be omitted entirely.
inspect_config = {
    "info_types": info_types,
    "min_likelihood": min_likelihood,
    "include_quote": include_quote,
    "limits": {"max_findings_per_request": max_findings},
}

# Convert the project id into a full resource id.
project_id = args.project_id
parent = f"projects/{project_id}"


def deidentify_content(item):
    # Call the API.
    response = dlp_client.deidentify_content(
        request={
            "parent": parent,
            "deidentify_config": deidentify_config,
            "inspect_config": inspect_config,
            "item": item
        }
    )
    return response


def inspect_content(item):
    # Call the API.
    response = dlp_client.inspect_content(
        request={
            "parent": parent,
            "inspect_config": inspect_config,
            "item": item
        }
    )
    return response


def print_findings(response):
    # Print out the results.
    if response.result.findings:
        for finding in response.result.findings:
            try:
                print("Quote: {}".format(finding.quote))
            except AttributeError:
                pass
            print("Info type: {}".format(finding.info_type.name))
            # Convert likelihood value to string representation.
            likelihood = finding.likelihood.name
            print("Likelihood: {}".format(likelihood))
    else:
        print("No findings.")


# The string to inspect
with open(input_path, 'r') as file:
    output_path = f'./output/{output_file}-out.json'

    # if file exists, overwrite
    with open(output_path, "w") as blank_output:
        blank_output.write('')

    # file size in bytes
    file_size = os.stat(input_path).st_size

    # byte limit for DLP API
    byte_limit = 500000
    byte_total = 0

    content = file.read(byte_limit)
    while True:
        # read until empty
        if not content:
            break
        item = {"value": content}

        if request_type == 'inspect':
            response = inspect_content(item)
            print_findings(response)
        elif request_type == 'deidentify':
            response = deidentify_content(item)

            # append masked json to output file
            output = open(output_path, 'a')
            output.write(response.item.value)
            output.close()
        else:
            print('Unknown --request-type')

        # print(response.item.value)
        # print_findings(response)

        # continue to next 500kb (limit 512kb)
        # upload to GCS if we want to avoid limit
        byte_total += byte_limit
        content = file.read(byte_limit)
        percent = round((byte_total/file_size)*100, 2)
        if percent > 100:
            percent = 100
        print(f'{percent}%')
    print('Complete')




