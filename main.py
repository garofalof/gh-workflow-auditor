import argparse
import os
import json

# Local imports
from auditor import content_analyzer
from action_auditor import action_audit
from github_wrapper import GHWrapper
from lib.logger import AuditLogger


"""
Input:
   repo_dict - dictionary defining repo information
   scan_folder - Location where the repo is cloned
Output:
    scan result (if any) in scan.log file.
Summary:
    For a given workflow dictionary (name, content) this
    function will call content_analyzer to audit the workflow
    for any potential vulnerabilities.
"""
# def repo_analysis(repo_url, repo_workflows):
#     for workflow in repo_workflows:
#         workflow_name = workflow['name']
#         workflow_content = workflow['content']
#         AuditLogger.info(f">> Scanning: {workflow_name}")
#         content_analyzer(content=workflow_content) # will print out security issues
def repo_analysis(repo_workflows, repo_path):
    repo_vulnerabilities = []

    for workflow in repo_workflows:
        workflow_name = workflow['name']
        workflow_content = workflow['content']
        AuditLogger.info(f">> Scanning: {workflow_name}")
        secrets_used, vulnerabilities = content_analyzer(content=workflow_content)

        repo_vulnerabilities.append({
            "workflow_name": workflow_name,
            "workflow_url": f"https://github.com/{repo_path}/blob/master/.github/workflows/{workflow_name}",
            "workflow_vulnerabilities": vulnerabilities,
            "num_secrets": secrets_used
        })

    return repo_vulnerabilities

def write_to_json(entity_data):
    output_file = 'output.json'
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            output_data = json.load(f)
            output_data.append(entity_data)
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=4)
    else:
        with open(output_file, 'w') as f:
            json.dump([entity_data], f, indent=4)

def main():
    # Supporting user provided arguments: type, and scan target.
    parser = argparse.ArgumentParser(description='Identify vulnerabilities in GitHub Actions workflow')
    parser.add_argument('--type',choices=['repo','org','user'],
                        help='Type of entity that is being scanned.')
    parser.add_argument('input',help='Org, user or repo name (owner/name)')
    args = parser.parse_args()

    gh = GHWrapper()

    target_type = args.type #repo, org, or user
    target_input = args.input #can be repo url, or a username for org/user

    if target_type == 'repo':
        repos = gh.get_single_repo(repo_name=target_input)
    else:
        count, repos = gh.get_multiple_repos(target_name=target_input,
                                    target_type=target_type)
        AuditLogger.info(f"Metric: Scanning total {count} repos")

    entity_data = {
        "entity_name": target_input,
        "entity_url": f"https://github.com/{target_input}",
        "repo_data": []
    }

    for repo_path, repo_workflows in repos.items():
        AuditLogger.info(f"> Starting audit of {repo_path}")
        repo_vulnerabilities = repo_analysis(repo_workflows, repo_path)
        entity_data['repo_data'].append({
            "repo_path": repo_path,
            "repo_url": f"https://github.com/{repo_path}",
            "repo_vulnerabilities": repo_vulnerabilities
        })

        # org_data = {
        #     "organization": target_input,
        #     "organization_url": f"https://github.com/{target_input}",
        #     "repos": repo_vulnerabilities
        # }
        # print(org_data)

    # for repo_dict in repos:
    #     AuditLogger.info(f"> Starting audit of {repo_dict}")
    #     repo_workflows = repos[repo_dict]
    #     repo_analysis(repo_workflows)

    AuditLogger.info(f"> Checking for supply chain attacks.")
    vulnerable_users = action_audit()
    entity_data['vulnerable_users'] = vulnerable_users

    write_to_json(entity_data)

main()