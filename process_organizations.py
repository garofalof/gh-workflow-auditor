import csv
import subprocess
import sys
import os
import json
import re
import pprint
from dotenv import load_dotenv
from collections import defaultdict
from github_wrapper import GHWrapper

def run_main_script(org_name, pat):
    command = f"PAT='{pat}' python3 main.py --type org {org_name}"
    subprocess.run(command, shell=True, check=True, env=os.environ.copy())

def run_trufflehog(org_name, pat):
    command = f"trufflehog github --org={org_name} --token={pat} --only-verified"
    subprocess.run(command, shell=True, check=True, env=os.environ.copy())

def process_organizations_csv():
    load_dotenv()
    pat = os.getenv("PAT")
    csv_file = 'organizations.csv'

    if not os.path.isfile(csv_file):
        print(f"CSV file '{csv_file}' not found.")
        sys.exit(1)

    with open(csv_file, 'r') as file:
        csv_reader = csv.DictReader(file)
        rows = list(csv_reader)
        start_index = 4204

        for i in range(start_index, len(rows)):
            print(f"Processing {i + 1} of {len(rows)}")
            github_org = rows[i]['github_org']
            run_main_script(github_org, pat)

def process_workflows():
    load_dotenv()
    gh_wrapper = GHWrapper()
    csv_file = 'vulnerabilities.csv'
    json_file = 'organizations.json'

    if not os.path.isfile(csv_file):
        print(f"CSV file '{csv_file}' not found.")
        sys.exit(1)

    organizations = defaultdict(lambda: {'workflows': []})
    workflow_paths = set()

    with open(csv_file, 'r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            entity_name = row['entity_name']
            entity_url = row['entity_url']
            workflow_path = row['workflow_path']
            workflow_paths.add(workflow_path)

            organizations[entity_name]['entity_name'] = entity_name
            organizations[entity_name]['entity_url'] = entity_url
            organizations[entity_name]['workflows'].append({
                'workflow_path': workflow_path,
                'vulnerabilities': [{
                    'vulnerability_name': row['vulnerability_name'],
                    'vulnerability_info': row['vulnerability_info']
                }]
            })

    i = 0
    org_totals = len(organizations.items())

    for entity_name, org_data in organizations.items():
        print(f">>> Processing entity {i + 1} of {org_totals}")
        j = 0

        for workflow in org_data['workflows']:
            print(f"Processing workflow {j + 1} of {len(org_data['workflows'])}")
            workflow_path = workflow['workflow_path']
            repo_url_parts = workflow_path.split('/')
            repo_name = repo_url_parts[3] + '/' + repo_url_parts[4]
            file_path = '/'.join(repo_url_parts[5:])
            repo_info = gh_wrapper.get_single_repo(repo_name)

            if repo_info:
                for repo_name, repo_workflows in repo_info.items():
                    for repo_workflow in repo_workflows:
                        if repo_workflow['name'] in file_path:
                            # workflow['workflow_content'] = repo_workflow['content']
                            workflow_content = repo_workflow['content']
                            workflow['workflow_content'] = json.dumps(workflow_content, indent=2)
                            break

            latest_authors = gh_wrapper.get_workflow_authors(repo_name, file_path)
            workflow['latest_authors'] = [{'email': author['email'], 'login': author['login'], 'committed_date': author['committed_date']} for author in latest_authors]

            j += 1
        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                output_data = json.load(f)
                output_data.append(org_data)
            with open(json_file, 'w') as f:
                json.dump(output_data, f, indent=4)
        else:
            with open(json_file, 'w') as f:
                json.dump([org_data], f, indent=4)

        i += 1

# def view_org_data(entity_name):
#     output_file = 'organizations.json'
#     org_data = next((org for org in json.load(open(output_file)) if org['entity_name'] == entity_name), None)
#     print(org_data)
def update_workflow_path(workflow_path):
    return re.sub(r'/blob/(?:master|main)/', '/blob/HEAD/', workflow_path)

# def process_organizations_json(file_path):
#     with open(file_path, 'r') as file:
#         organizations = json.load(file)

#     result = []

#     for org in organizations:
#         workflows = org['workflows']

#         for workflow in workflows:
#             workflow_path = workflow['workflow_path']
#             workflow_content = workflow['workflow_content']
#             workflow_vulnerabilities = workflow['vulnerabilities']

#             result.append({
#                 'workflow_path': workflow_path,
#                 'workflow_content': workflow_content,
#                 'vulnerabilities': workflow_vulnerabilities
#             })



#     start, end = 180, 199
#     sliced_result = result[start:end]

#     for i, workflow in enumerate(sliced_result):
#         print(f'Workflow {i + 1}:\n')
#         pp = pprint.PrettyPrinter(indent=4)
#         pp.pprint(workflow)
#         print('\n')

#     print(f"Sliced result length: {len(sliced_result)}")
# def process_organizations_json(file_path):
#     with open(file_path, 'r') as file:
#         organizations = json.load(file)

#     result = []
#     seen_workflow_paths = set()
#     vulnerability_names = ["Remote Code Execution via Unsanitized Input in Workflow Steps", "Remote Code Execution via Environment Variable Injection in GitHub Context"]

#     for org in organizations:
#         workflows = org['workflows']

#         for workflow in workflows:
#             workflow_path = workflow['workflow_path']
#             workflow_content = workflow['workflow_content']
#             workflow_vulnerabilities = workflow['vulnerabilities']

#             # Check if the workflow has the specified vulnerability
#             if any(vuln['vulnerability_name'] in vulnerability_names for vuln in workflow_vulnerabilities):
#                 if workflow_path not in seen_workflow_paths:
#                     seen_workflow_paths.add(workflow_path)
#                     result.append({
#                         'workflow_path': workflow_path,
#                         'workflow_content': workflow_content,
#                         'vulnerabilities': workflow_vulnerabilities
#                     })

#     start, end = 125, 160
#     sliced_result = result[start:end]

#     for i, workflow in enumerate(sliced_result):
#         print(f'Workflow {i + 1}:\n')
#         pp = pprint.PrettyPrinter(indent=4)
#         pp.pprint(workflow)
#         print('\n')

#     print(f"Sliced result length: {len(sliced_result)}\n")
#     print(f"Processed {start + 1} through {end} of {len(result)} workflows")



def main():
    process_organizations_csv()







if __name__ == '__main__':
    main()