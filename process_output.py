import json
import csv
import re

def write_vulnerabilities():
    # Patterns for workflow names to filter vulnerabilities
    patterns = [
        "Remote Code Execution via Unsanitized Input in Workflow Steps",
        "Remote Code Execution via Environment Variable Injection in GitHub Context",
        "Security Bypass via Malicious Pull Request in GitHub Actions Checkout Step",
        "Supply Chain Risk: Username Renaming in Workflows Without Validation"
    ]

    # Regular expression pattern for matching any of the specified patterns
    pattern_regex = re.compile('|'.join(map(re.escape, patterns)))

    # Read JSON data from output.json
    with open('output.json', 'r') as json_file:
        data = json.load(json_file)

    # Open CSV file for writing
    with open('vulnerabilities.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write header row
        writer.writerow(['entity_name', 'entity_url', 'workflow_name', 'workflow_path', 'vulnerability_name', 'vulnerability_info', 'num_secrets'])

        # Iterate through each entity in the JSON data
        for entity in data:
            entity_name = entity['entity_name']
            entity_url = entity['entity_url']

            # Iterate through each repo_data in the entity
            for repo_data in entity['repo_data']:
                repo_path = repo_data['repo_path']

                # Iterate through each repo_vulnerability in the repo_data
                for repo_vulnerability in repo_data['repo_vulnerabilities']:
                    workflow_name = repo_vulnerability['workflow_name']
                    workflow_url = repo_vulnerability['workflow_url']
                    workflow_vulnerabilities = repo_vulnerability['workflow_vulnerabilities']

                    if workflow_vulnerabilities:
                        for vulnerability in workflow_vulnerabilities:
                            vulnerability_name = vulnerability.get('vulnerability_name', '')
                            vulnerability_info = vulnerability.get('vulnerability_info', '')
                            num_secrets = len(repo_vulnerability.get('num_secrets', []))

                            if pattern_regex.search(vulnerability_name):
                                # Write row to CSV
                                writer.writerow([entity_name, entity_url, workflow_name, workflow_url, vulnerability_name, vulnerability_info, num_secrets])



def write_external_resources():
    # Patterns for workflow names to filter vulnerabilities
    patterns = [
     "Cloud Resource Access",
     "Kubernetes Resource Access",
     "External Resource Access"
    ]

    # Regular expression pattern for matching any of the specified patterns
    pattern_regex = re.compile('|'.join(map(re.escape, patterns)))

    # Read JSON data from output.json
    with open('output.json', 'r') as json_file:
        data = json.load(json_file)

    # Open CSV file for writing
    with open('external_resources.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write header row
        writer.writerow(['entity_name', 'entity_url', 'workflow_name', 'workflow_path', 'vulnerability_name', 'vulnerability_info'])

        # Iterate through each entity in the JSON data
        for entity in data:
            entity_name = entity['entity_name']
            entity_url = entity['entity_url']

            # Iterate through each repo_data in the entity
            for repo_data in entity['repo_data']:
                repo_path = repo_data['repo_path']

                # Iterate through each repo_vulnerability in the repo_data
                for repo_vulnerability in repo_data['repo_vulnerabilities']:
                    workflow_name = repo_vulnerability['workflow_name']
                    workflow_url = repo_vulnerability['workflow_url']
                    workflow_vulnerabilities = repo_vulnerability['workflow_vulnerabilities']

                    if workflow_vulnerabilities:
                        for vulnerability in workflow_vulnerabilities:
                            vulnerability_name = vulnerability.get('vulnerability_name', '')
                            vulnerability_info = vulnerability.get('vulnerability_info', '')

                            if pattern_regex.search(vulnerability_name):
                                # Write row to CSV
                                writer.writerow([entity_name, entity_url, workflow_name, workflow_url, vulnerability_name, vulnerability_info])


def write_secrets():
    # Function to extract unique secrets from repo_vulnerabilities
    def extract_secrets(repo_vulnerabilities):
        secrets = set()
        for vulnerability in repo_vulnerabilities:
            secrets.update(vulnerability.get('num_secrets', []))
        return secrets
    # Read JSON data from output.json
    with open('output.json', 'r') as json_file:
        data = json.load(json_file)

    # Extract unique secrets
    all_secrets = set()
    for entity in data:
        for repo_data in entity['repo_data']:
            all_secrets.update(extract_secrets(repo_data['repo_vulnerabilities']))

    # Write unique secrets to secrets.csv
    with open('secrets.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['Secrets'])
        writer.writerows([[secret] for secret in all_secrets])

write_secrets()