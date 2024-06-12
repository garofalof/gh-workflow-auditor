import json
import re
import csv


def format_vulnerable_inputs(vulnerable_inputs):
    if vulnerable_inputs is None:
        return None

    num_inputs = len(vulnerable_inputs)

    if num_inputs == 0:
        return None
    elif num_inputs == 1:
        return vulnerable_inputs[0]
    elif num_inputs == 2:
        return f"{vulnerable_inputs[0]} and {vulnerable_inputs[1]}"
    else:
        formatted_inputs = ", ".join(vulnerable_inputs[:-1])
        formatted_inputs += f", and {vulnerable_inputs[-1]}"
        return formatted_inputs


def process_vulnerabilities(input_file, orgs_json_file, output_file):
    # Load the organizations and vulnerabilities data from the provided JSON files
    with open(orgs_json_file, 'r') as file:
        organizations = json.load(file)
    with open(input_file, 'r') as file:
        vulnerabilities = json.load(file)

    # Open the CSV file for writing
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['github_org', 'workflow_path', 'exploit_type',
                      'exploit_severity', 'exploit_info', 'vulnerable_inputs']
        fieldnames += [f'author_{i}' for i in range(1, 11)]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        # Process each vulnerability
        for vul in vulnerabilities:
            workflow_path = vul['workflow_path']
            exploit_type = vul.get('exploit_type')
            exploit_severity = vul.get('exploit_severity')
            exploit_info = vul.get('exploit_info')
            vulnerable_inputs = vul.get('vulnerable_inputs', None)
            formatted_inputs = format_vulnerable_inputs(vulnerable_inputs)
            github_org = re.search(
                r"github\.com/([^/]+)/", workflow_path).group(1)

            found_workflow = next(
                (workflow for entity in organizations for workflow in entity[
                 "workflows"] if workflow["workflow_path"] == workflow_path),
                None
            )
            if found_workflow:
                valid_authors = [
                    author for author in found_workflow['latest_authors']
                    if ("noreply" not in author['email'] and "bot@" not in author['email'])
                ]
                selected_authors = [author['email']
                                    for author in valid_authors[:10]]
            else:
                print(f">>> Workflow not found for path: {workflow_path}")
                selected_authors = [None] * 10

             # Write the row to the CSV file
            row_data = {
                'github_org': github_org,
                'workflow_path': workflow_path,
                'exploit_type': exploit_type,
                'exploit_severity': exploit_severity,
                'exploit_info': exploit_info,
                'vulnerable_inputs': formatted_inputs,
            }
            # Write selected authors to corresponding columns
            for i, author in enumerate(selected_authors, start=1):
                row_data[f'author_{i}'] = author
            writer.writerow(row_data)


def extract_vulnerable_inputs(exploit_info):
    # Regular expression to find inputs starting with 'github.event' or 'github.head_ref'
    pattern = r'github\.(event\.\w+(?:\.\w+)*|head_ref)'

    # Extract vulnerable inputs using regex
    vulnerable_inputs = re.findall(pattern, exploit_info)

    for i, input in enumerate(vulnerable_inputs):
        vulnerable_inputs[i] = 'github.' + input

    return vulnerable_inputs


def read_json_file(file_name):
    with open(file_name, 'r') as file:
        result = json.load(file)
        return result


def write_json_file(file_name, data):
    with open(file_name, 'w') as f:
        json.dump(data, f, indent=4)


def severity_level(severity, return_type):
    if return_type == "number":
        severity_levels = {
            'very low': 1,
            'low': 2,
            'medium': 3,
            'high': 4,
            'very high': 5
        }
        return severity_levels.get(severity.lower(), 0)
    else:
        severity_levels = {
            1: 'very low',
            2: 'low',
            3: 'medium',
            4: 'high',
            5: 'very high'
        }
        return severity_levels.get(severity, None)


def combine_and_save():
    untrusted_inputs_file = "untrusted_input_vuls.json"
    untrusted_inputs_exploits = read_json_file(untrusted_inputs_file)
    untrusted_workflows = {}

    for _, exploit in enumerate(untrusted_inputs_exploits):
        exploit_info = exploit['exploit_info']
        vulnerable_inputs = extract_vulnerable_inputs(exploit_info)
        exploit['vulnerable_inputs'] = vulnerable_inputs

        workflow_url = exploit['workflow_path']
        untrusted_workflows[workflow_url] = exploit

    pr_target_vulnerabilities_file = "pr_target_vuls.json"
    pr_target_exploits = read_json_file(pr_target_vulnerabilities_file)

    combined_vulnerabilities = {}
    edited_count = 0
    unedited_count = 0

    for exploit in untrusted_inputs_exploits + pr_target_exploits:
        workflow_path = exploit['workflow_path']
        if workflow_path in combined_vulnerabilities:
            print(f">>> Found duplicate for {workflow_path}")
            # If the workflow path already exists, combine the vulnerabilities
            existing_exploit = combined_vulnerabilities[workflow_path]
            existing_severity = severity_level(
                existing_exploit['exploit_severity'], "number")
            new_severity = severity_level(
                exploit['exploit_severity'], "number")
            highest_severity = max(existing_severity, new_severity)

            print(
                f"Comparing existing severity of {existing_severity} with new severity of {new_severity}...")
            existing_exploit['exploit_type'] = "Both"
            existing_exploit['exploit_info'] += f". {exploit['exploit_info']}"
            existing_exploit['exploit_severity'] = severity_level(
                highest_severity, "string")
            print(
                f"Finalized w/ severity of: {existing_exploit['exploit_severity']}")

            if 'vulnerable_inputs' in exploit:
                existing_exploit['vulnerable_inputs'] = exploit['vulnerable_inputs']
            edited_count += 1
        else:
            # Otherwise, add the new vulnerability
            combined_vulnerabilities[workflow_path] = exploit
            unedited_count += 1

    result_data = []

    for _, exploit in combined_vulnerabilities.items():
        exploit['exploit_severity'] = exploit['exploit_severity'].lower()
        result_data.append(exploit)

    output_file_name = "combined_vulnerabilities.json"

    write_json_file(output_file_name, result_data)


def process_csv(file_path):
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        authors = set()
        emails = {}
        count = 0

        for row in reader:
            author = row['author']
            workflow_path = row['workflow_path']
            vulnerable_inputs = row['vulnerable_inputs']
            exploit_type = row['exploit_type']
            exploit_severity = row['exploit_severity']
            split_paths = workflow_path.split('/')
            repo_name = f'{split_paths[3]}/{split_paths[4]}'

            if author and exploit_type == "Untrusted Input" and exploit_severity in ["high", "very high"]:
                if author not in emails:
                    emails[author] = {}
                if repo_name not in emails[author]:
                    emails[author][repo_name] = []
                emails[author][repo_name].append(
                    (workflow_path, vulnerable_inputs))
                count += 1
                authors.add(author)

        sorted_authors = sorted(authors, key=lambda x: x.lower())

        for author in sorted_authors:
            if author in emails:
                workflows = emails[author]
                email = render_vulnerable_input_email(author, workflows)
                # email = render_email(author, workflows)
                print(f"Email for {author}:\n")
                print(
                    f"Subject: Potential security vulnerability in your GitHub {'workflow' if len(workflows) == 1 else 'workflows'}\n")
                print(email)
                print("------------------------")

        print(f">>> Total count is {count}")


def render_pr_target_email(author, workflows):
    email_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: Arial, sans-serif;
            font-size: 10pt;
        }}
    </style>
    </head>
    <body>
    <p>Hey there! I'm Francesco, a Product Engineer at Teleport. In doing some security research on open-source projects, I've noticed that the following {'workflow' if len(workflows) == 1 else 'workflows'} you've recently contributed to may be vulnerable due to unsafe usage of the <code>pull_request_target</code> trigger:</p>

    <ul>
        {"".join([f"<li><a href='{workflow}'>{workflow}</a></li>" for workflow in workflows])}
    </ul>

    <p>{'This workflow appears' if len(workflows) == 1 else 'These workflows appear'} to be checking out and executing code from untrusted PRs, which could allow attackers to inject malicious scripts and compromise the repository.</p>

    <p>If you have a chance, I've listed some resources below that provide alternatives for mitigating this risk:</p>

    <ul>
        <li><a href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/">Preventing PWN Requests in GitHub Actions</a></li>
        <li><a href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions">Security hardening for GitHub Actions</a></li>
    </ul>

    <p>If you have any questions or would like to discuss further, feel free to reach out. I'm happy to help!</p>

    <p>Best,<br>
    Francesco</p>
    </body>
    </html>
    """
    return email_template.strip()


def render_vulnerable_input_email(author, workflows):
    workflow_count = sum(len(wf) for wf in workflows.values())

    email_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: Arial, sans-serif;
            font-size: 10pt;
        }}
    </style>
    </head>
    <body>
    <p>Hey there! I'm Francesco, a Product Engineer at Teleport. In doing some security research on open-source projects, I've noticed that the following {'workflow' if workflow_count == 1 else 'workflows'} you've recently contributed to may benefit from additional review regarding the handling of user input:</p>

    <ul>
        {"".join([render_workflow_list(repo_name, workflows[repo_name]) for repo_name in workflows])}
    </ul>

    <p>As a contributor, I figured you might have better insight into the project's security requirements and whether any additional mitigation is necessary. If helpful, I've provided some resources below that provide alternatives for handling untrusted inputs:</p>

    <ul>
        <li><a href="https://securitylab.github.com/research/github-actions-untrusted-input/">Untrusted input in GitHub Actions</a></li>
        <li><a href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions">Security hardening for GitHub Actions</a></li>
    </ul>

    <p>If you have any questions or would like to discuss further, feel free to reach out. I'm happy to help!</p>

    <p>Best,<br>
    Francesco</p>
    </body>
    </html>
    """
    return email_template.strip()


def render_workflow_list(repo_name, workflows):
    workflow_list = "\n".join(
        [f"<li><a href='{workflow_path}'>{workflow_path}</a>&mdash;review the usage of <code>{vulnerable_inputs}</code></li>" for workflow_path, vulnerable_inputs in workflows])
    return workflow_list


def main():
    input_file = 'combined_vulnerabilities.json'
    orgs_json_file = 'organizations.json'
    output_file = 'exploit_data.csv'

    # process_vulnerabilities(input_file, orgs_json_file, output_file)
    process_csv(output_file)


if __name__ == '__main__':
    main()
