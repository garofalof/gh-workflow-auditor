import os
import sys
import time
import requests
from lib.logger import AuditLogger

from query_data import return_query, validation_query

"""
Input:
    token - GitHub PAT. Retrieved from environment variable.

Summary:
    This wrapper uses GitHub's GraphQL API and repository(ies)
    for the provided scan target. In addition, it is also used
    at the end of the workflow for stale account checks.
"""
class GHWrapper():
    def __init__(self):
        self.token = os.environ.get('PAT',None)
        self.token = self.token if self.validate_token() else None
        if self.token is None:
            AuditLogger.warning("No valid GitHub API Key was supplied.")
            sys.exit()

    def validate_token(self):
        header = {"Authorization":f"token {self.token}"}
        url = "https://api.github.com"
        validation_req = requests.get(url=url, headers=header)
        valid_status = True
        if validation_req.status_code == 401:
            valid_status = False
        else:
            valid_status = True
        return valid_status

    def call_graphql(self, query):
        url = 'https://api.github.com/graphql'
        headers = {
            'Authorization':f"Bearer {self.token}",
            'Content-Type':'application/json'
        }

        while True:
            response = requests.post(url=url, json={'query': query}, headers=headers)
            remaining_points = int(response.headers.get('x-ratelimit-remaining', 0))
            used_points = int(response.headers.get('x-ratelimit-used', 0))
            reset_time = int(response.headers.get('x-ratelimit-reset', 0))

            AuditLogger.info(f"Remaining rate limit points: {remaining_points}")
            AuditLogger.info(f"Used rate limit points: {used_points}")

            if remaining_points > 0:
                if response.status_code == 200:
                    return response.json()
                else:
                    message = response.text
                    AuditLogger.error(f"GitHub GraphQL Query failed: {message}")
                    raise RuntimeError(f"GitHub GraphQL Query failed with error: {message}")
            else:
                wait_time = reset_time - int(time.time())
                AuditLogger.info(f"Rate limit exceeded. Waiting for {wait_time} seconds.")
                time.sleep(wait_time + 5)

    def repo_node_parser(self,repo_node):
        workflow_object = repo_node['object']
        repo_workflows = []
        if workflow_object:
            workflows = workflow_object['entries']
            for workflow in workflows:
                workflow_name = workflow['name']
                if workflow.get('object',None):
                    workflow_text = workflow['object'].get('text',None)
                workflow_ext = workflow_name.split('.')[-1]
                if workflow_ext == "yml" or workflow_ext == "yaml":
                    repo_workflows.append({'name':workflow_name,'content':workflow_text})
        return repo_workflows

    def get_single_repo(self, repo_name):
        repos_all = {}
        repo_query = return_query('repository',
                                repo_name)
        repos = self.call_graphql(repo_query)
        if repos.get('errors') is None:
            repo_node  = repos['data']['repository']
            repo_name = repo_node['nameWithOwner']
            repo_workflows = self.repo_node_parser(repo_node)
            if repo_workflows: # this repo has workflows
                repos_all[repo_name] = repo_workflows
            else:
                AuditLogger.debug(f"Repo {repo_name} has no workflow.")
        return repos_all

    def get_multiple_repos(self,target_name,target_type='org'):
        AuditLogger.info(f"---- Getting repos for {target_name}----")
        repos_all = {}
        query_type = {'org':'organization','user':'user','repo':'repository'}
        retry_count = 0
        max_retries = 5
        next_cursor = None
        repo_batch_size = 100  # Initial batch size

        while retry_count < max_retries: # Retry up to 5 times for the current batch
            try:
                has_more = True # for pagination loop
                count = 0
                while has_more:
                    query = return_query(query_type[target_type],
                                    target_name, next_cursor, repo_batch_size)
                    repos = self.call_graphql(query)
                    if repos.get('errors') is None:
                        for repo in repos['data'][query_type[target_type]]['repositories']['edges']:
                            repo_node = repo['node']
                            repo_name = repo_node['nameWithOwner']
                            repo_workflows = self.repo_node_parser(repo_node)
                            if repo_workflows:
                                repos_all[repo_name] = repo_workflows
                                count += 1
                            else:
                                AuditLogger.debug(f"Repo {repo_name} has no workflow.")
                        has_more = repos['data'][query_type[target_type]]['repositories']['pageInfo']['hasNextPage']
                        next_cursor = repos['data'][query_type[target_type]]['repositories']['pageInfo']['endCursor']
                        if has_more:
                            AuditLogger.info(f"> Retrieve next batch of {repo_batch_size} repos.")
                    else:
                        AuditLogger.error("GraphQL response had error.")
                        raise Exception("GraphQL query failed")

                # If we reach here, all repositories have been fetched successfully
                return count, repos_all
            except Exception as e:
                # Log the error and attempt again if it's not the last attempt
                retry_count += 1
                AuditLogger.error(f"Error fetching repositories: {str(e)}")
                if retry_count < max_retries:
                    repo_batch_size //= 2  # Reduce batch size by half
                    AuditLogger.info(f"Retry attempt {retry_count} for the current batch with a batch size of {repo_batch_size}.")
                    time.sleep(5)

        return count, repos_all

    def stale_checker(self,username):
        valid = False
        if username:
            user_query = validation_query(username, 'user')
            is_it_user = self.call_graphql(query=user_query)['data']['user']
            org_query = validation_query(username, 'organization')
            is_it_org = self.call_graphql(query = org_query)['data']['organization']
            if is_it_user or is_it_org:
                valid = True
        return valid



