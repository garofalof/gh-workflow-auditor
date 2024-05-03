import csv
import subprocess
import sys
import os
from dotenv import load_dotenv

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

        for i, row in enumerate(csv_reader):
            if i >= 0:
                github_org = row['github_org']
                run_main_script(github_org, pat)

if __name__ == '__main__':
    process_organizations_csv()