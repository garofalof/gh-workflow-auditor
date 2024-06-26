from github_wrapper import GHWrapper
from lib.logger import AuditLogger
from pathlib import Path
import re

gh = GHWrapper()

def read_actions_file():
    array_of_usernames = []
    with open('actions.txt','r') as lines:
        for line in lines:
            username = line.split('/')[0]
            username_regex = re.compile("[A-Za-z0-9-]*")
            if username_regex.fullmatch(username):
                if username not in array_of_usernames:
                    array_of_usernames.append(username)
    return array_of_usernames

def check_usernames(username_list):
    vulnerable_users = []

    for username in username_list:
        renamed_or_not = gh.stale_checker(username=username)
        if not renamed_or_not:
            vulnerable_users.append({
                "username": username,
                "vulnerability_name": "Supply Chain Risk: Username Renaming in Workflows Without Validation",
                "vulnerability_info": f"Supply chain. {username} was renamed but used in workflows. Signup the username at https://github.com to make sure."
            })
            AuditLogger.warning(f"Security Issue: Supply chain. {username} was renamed but used in workflows. Signup the username at https://github.com to make sure.")
        
    
    return vulnerable_users
            

def action_audit():
    if Path('actions.txt').exists():
        usernames = read_actions_file()
        vulnerable_users = check_usernames(usernames)
        Path('actions.txt').unlink()
        
        return vulnerable_users
    else:
        AuditLogger.info("No actions.txt file to scan. Supply chain scan complete.")

