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
    action_storage = open('actions.txt', 'a+')
    try:
        for action in actions:
            for step_number, step_dict in action.items():
                action_name = step_dict.get('uses')
                action_storage.write(f"{action_name}\n")
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
        AuditLogger.error(f"Error analyzing actions: {str(e)}")
    finally:
        action_storage.close()
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

                external_resource_patterns = vuln_analyzer.detect_external_resource_patterns(content)
                if external_resource_patterns:
                    vulnerabilities.append({
                        "vulnerability_name": "External Resource Access",
                        "vulnerability_info": f"Usage of {', '.join(set(pattern for patterns in external_resource_patterns.values() for pattern in patterns))} found."
                    })
                    AuditLogger.info(f"Usage of {', '.join(set(pattern for patterns in kubernetes_patterns.values() for pattern in patterns))} found.")

        return secrets_used, vulnerabilities

    except Exception as e:
        AuditLogger.error(f"Error in content_analyzer: {str(e)}")
        return [], []