# from workflow import WorkflowParser, WorkflowVulnAudit
# from lib.logger import AuditLogger

# vuln_analyzer = WorkflowVulnAudit()

# def risky_trigger_analysis(identified_triggers):
#     return_triggers = []
#     for trigger in identified_triggers:
#         risky_or_not = vuln_analyzer.risky_trigger(trigger_name=trigger)
#         if risky_or_not:
#             return_triggers.append(trigger)
#     return return_triggers


# """
# Input:
#    content - YAML content read from the workflow files.
# Output:
#     scan result (if any) in scan.log file.
# Summary:
#     This is the critical part of the whole tool. It parses the
#     YAML content to identify security issues. It does so by:
#     parsing YAML to JSON, identifying keys such as event triggers,
#     jobs and steps. It then checks the identified key-value pairs
#     against known risks through WorkflowParser and WorkflowVulnAudit.
# """
# def content_analyzer(content):
#     risky_triggers = []
#     all_actions = []
#     commands = []
#     environs = {}
#     checked_action = []
#     workflow_client = WorkflowParser(content)
#     vulnerabilities = []
#     secrets_used = []

#     try:
#         if workflow_client.parsed_content and not workflow_client.parsed_content.get('failed',None): # Sanity check to make sure proper YAML was given.
#             event_triggers = workflow_client.get_event_triggers() # Identify what event(s) will start the workflow.
#             secrets = vuln_analyzer.get_secrets(content) # get all the secrets in the workflow. (Uses regex). This helps understand impact.
#             all_jobs = workflow_client.get_jobs() # Identify all jobs in the workflow. Stored as dictionary

#             counter = 1 # Counter used to identify which line of code is vulnerable.

#             if secrets:
#                 AuditLogger.info(f">>> Secrets used in workflow: {','.join(secrets)}")
#                 secrets_used.extend(secrets)

#             # Retrieve and store all needed information for a workflow run for analysis.
#             if all_jobs:
#                 for job in all_jobs:
#                     steps = all_jobs[job].get('steps',None)
#                     if not steps:
#                         steps = [all_jobs[job]]
#                     try:
#                         environs.update(all_jobs[job].get('env',{}))
#                     except:
#                         AuditLogger.info(">> Environ variable is malformed")
#                     for step_number,step in enumerate(steps):
#                         actions, run_command, with_input, step_environ = workflow_client.analyze_step(step)
#                         if actions:
#                             all_actions.append({f"Job{counter}.Step{step_number+1}":step})
#                         if step_environ:
#                             if isinstance(step_environ, str):
#                                 step_environ = {f"{step_number}{step}":step_environ}
#                             environs.update(step_environ)
#                         if run_command:
#                             commands.append({f"Job{counter}.Step{step_number+1}":step})
#                     counter +=1

#                 # Start analyzing the retrieved information.
#                 try:
#                     # Analyzes event triggers to see if they are user controlled.
#                     risky_triggers = risky_trigger_analysis(identified_triggers=event_triggers)

#                     # Analyzes commands called by Steps.
#                     for command in commands:
#                         for step_number, step_dict in command.items():
#                             risky_command = vuln_analyzer.risky_command(command_string=step_dict['run'])
#                             if risky_command:
#                                 for regex, matched_strings in risky_command.items():
#                                     if regex == 'environ_regex': # not all environments are bad. Check if this environment is user controlled.
#                                         # get the key out of the matched strings. We use this to check if the environ variable stores any user controlled input.
#                                         for environ_variable in matched_strings:
#                                             environ_variable = environ_variable.strip('${{').strip('}}').split('.')[1].strip()
#                                             # get environ value
#                                             environ_var_value = environs.get(environ_variable,None)
#                                             if environ_var_value:
#                                                 risky_env = vuln_analyzer.risky_command(command_string=environ_var_value)
#                                                 if risky_env and list(risky_env.keys())[0] != 'environ_regex':
#                                                     vulnerabilities.append({
#                                                         "vulnerability_name": "Remote Code Execution via Environment Variable Injection in GitHub Context",
#                                                         "vulnerability_info": f"RCE detected with {regex} in {step_number}: ENV variable {environ_variable} is called through GitHub context and takes user input {environ_var_value}"
#                                                     })
#                                                     AuditLogger.warning(f">>> Security Issue: RCE detected with {regex} in {step_number}: ENV variable {environ_variable} is called through GitHub context and takes user input {environ_var_value}")
#                                     else:
#                                         vulnerabilities.append({
#                                             "vulnerability_name": f"Remote Code Execution via Unsanitized Input in Workflow Steps",
#                                             "vulnerability_info": f"RCE detected with {regex} in {step_number}: Usage of {','.join(matched_strings)} found."
#                                         })
#                                         AuditLogger.warning(f">>> Security Issue: RCE detected with {regex} in {step_number}: Usage of {','.join(matched_strings)} found.")

#                     # Some actions combined with triggers can be bad. Check for those cases.
#                     action_storage = open('actions.txt','a+')
#                     for action in all_actions:
#                         for step_number, step_dict in action.items():
#                             action_name = step_dict.get('uses',None)
#                             action_storage.write(f"{action_name}\n")
#                             if 'actions/checkout' in action_name:
#                                 # check if specific branch is checked out
#                                 if step_dict.get('with',None):
#                                     if step_dict['with'].get('ref',None):
#                                         ref_value = step_dict['with'].get('ref')
#                                         risky_commits = vuln_analyzer.risky_commit(referenced=ref_value)
#                                         if risky_commits:
#                                             if 'pull_request_target' in risky_triggers:
#                                                 vulnerabilities.append({
#                                                     "vulnerability_name": "Security Bypass via Malicious Pull Request in GitHub Actions Checkout Step",
#                                                     "vulnerability_info": f"Malicious pull request used in actions/checkout. Vulnerable step: {step_number}"
#                                                 })
#                                                 AuditLogger.warning(f">>> Security Issue: Malicious pull request used in actions/checkout. Vulnerable step: {step_number} ")
#                     action_storage.close()
#                 except Exception as workflow_err:
#                     AuditLogger.info(f">>> Error parsing workflow. Error is {str(workflow_err)}")
#     except Exception as e:
#         AuditLogger.info(f">>> Error in content_analyzer. Error is {str(e)}")

#     return secrets_used, vulnerabilities
from workflow import WorkflowParser, WorkflowVulnAudit
from lib.logger import AuditLogger

vuln_analyzer = WorkflowVulnAudit()

def analyze_triggers(triggers):
    try:
        return [trigger for trigger in triggers if vuln_analyzer.risky_trigger(trigger)]
    except Exception as e:
        AuditLogger.error(f"Error analyzing triggers: {str(e)}")
        return []

def analyze_commands(commands, environs):
    vulnerabilities = []
    for command in commands:
        for step_number, step_dict in command.items():
            try:
                command_string = step_dict['run']
                risky_command = vuln_analyzer.risky_command(command_string)
                if risky_command:
                    vulnerabilities.extend(process_risky_command(risky_command, step_number, command_string, environs))
            except KeyError as e:
                AuditLogger.warning(f"Missing 'run' key in step {step_number}: {str(e)}")
            except Exception as e:
                AuditLogger.error(f"Error analyzing command in step {step_number}: {str(e)}")
    return vulnerabilities

def process_risky_command(risky_command, step_number, command_string, environs):
    vulnerabilities = []
    for regex, matched_strings in risky_command.items():
        try:
            if regex == 'environ_regex':
                vulnerabilities.extend(process_environ_variable(matched_strings, step_number, environs))
            else:
                vulnerabilities.append({
                    "vulnerability_name": "Remote Code Execution via Unsanitized Input in Workflow Steps",
                    "vulnerability_info": f"RCE detected with {regex} in {step_number}: Usage of {','.join(matched_strings)} found."
                })
                AuditLogger.warning(f">>> Security Issue: RCE detected with {regex} in {step_number}: Usage of {','.join(matched_strings)} found.")
        except Exception as e:
            AuditLogger.error(f"Error processing risky command in step {step_number}: {str(e)}")
    return vulnerabilities

def process_environ_variable(matched_strings, step_number, environs):
    vulnerabilities = []
    for environ_variable in matched_strings:
        try:
            environ_variable = environ_variable.strip('${{').strip('}}').split('.')[1].strip()
            environ_var_value = environs.get(environ_variable)
            if environ_var_value:
                risky_env = vuln_analyzer.risky_command(environ_var_value)
                if risky_env and list(risky_env.keys())[0] != 'environ_regex':
                    vulnerabilities.append({
                        "vulnerability_name": "Remote Code Execution via Environment Variable Injection in GitHub Context",
                        "vulnerability_info": f"RCE detected in {step_number}: ENV variable {environ_variable} is called through GitHub context and takes user input {environ_var_value}"
                    })
                    AuditLogger.warning(f">>> Security Issue: RCE detected in {step_number}: ENV variable {environ_variable} is called through GitHub context and takes user input {environ_var_value}")
        except Exception as e:
            AuditLogger.error(f"Error processing environment variable in step {step_number}: {str(e)}")
    return vulnerabilities

def analyze_actions(actions, risky_triggers):
    vulnerabilities = []
    for action in actions:
        for step_number, step_dict in action.items():
            try:
                action_name = step_dict.get('uses')
                if 'actions/checkout' in action_name and step_dict.get('with', {}).get('ref'):
                    ref_value = step_dict['with']['ref']
                    risky_commits = vuln_analyzer.risky_commit(ref_value)
                    if risky_commits and 'pull_request_target' in risky_triggers:
                        vulnerabilities.append({
                            "vulnerability_name": "Security Bypass via Malicious Pull Request in GitHub Actions Checkout Step",
                            "vulnerability_info": f"Malicious pull request used in actions/checkout. Vulnerable step: {step_number}"
                        })
                        AuditLogger.warning(f">>> Security Issue: Malicious pull request used in actions/checkout. Vulnerable step: {step_number} ")
            except Exception as e:
                AuditLogger.error(f"Error analyzing action in step {step_number}: {str(e)}")
    return vulnerabilities

def content_analyzer(content):
    try:
        workflow_client = WorkflowParser(content)
        vulnerabilities = []
        secrets_used = []

        if workflow_client.parsed_content and not workflow_client.parsed_content.get('failed'):
            event_triggers = workflow_client.get_event_triggers()
            secrets = vuln_analyzer.get_secrets(content)
            all_jobs = workflow_client.get_jobs()
            environs = {}
            commands = []
            all_actions = []

            if secrets:
                AuditLogger.info(f">>> Secrets used in workflow: {','.join(secrets)}")
                secrets_used.extend(secrets)

            if all_jobs:
                for job in all_jobs:
                    steps = all_jobs[job].get('steps', [all_jobs[job]])
                    environs.update(all_jobs[job].get('env', {}))
                    for step_number, step in enumerate(steps, start=1):
                        actions, run_command, _, step_environ = workflow_client.analyze_step(step)
                        if actions:
                            all_actions.append({f"Step{step_number}": step})
                        if step_environ:
                            environs.update({f"Step{step_number}": step_environ} if isinstance(step_environ, str) else step_environ)
                        if run_command:
                            commands.append({f"Step{step_number}": step})

                risky_triggers = analyze_triggers(event_triggers)
                vulnerabilities.extend(analyze_commands(commands, environs))
                vulnerabilities.extend(analyze_actions(all_actions, risky_triggers))

                cloud_commands = vuln_analyzer.detect_cloud_commands(content)
                if cloud_commands:
                    vulnerabilities.append({
                        "vulnerability_name": "Cloud Resource Access",
                        "vulnerability_info": f"Usage of {', '.join(set(command for commands in cloud_commands.values() for command in commands))} found."
                    })
                    AuditLogger.info(f">>> Machine ID Candidate: Usage of {', '.join(set(command for commands in cloud_commands.values() for command in commands))} found.")

                kubernetes_patterns = vuln_analyzer.detect_kubernetes_patterns(content)
                if kubernetes_patterns:
                    vulnerabilities.append({
                        "vulnerability_name": "Kubernetes Resource Access",
                        "vulnerability_info": f"Usage of {', '.join(set(pattern for patterns in kubernetes_patterns.values() for pattern in patterns))} found."
                    })
                    AuditLogger.info(f"Usage of {', '.join(set(pattern for patterns in kubernetes_patterns.values() for pattern in patterns))} found.")

        return secrets_used, vulnerabilities

    except Exception as e:
        AuditLogger.error(f"Error in content_analyzer: {str(e)}")
        return [], []