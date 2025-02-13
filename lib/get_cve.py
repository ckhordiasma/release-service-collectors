#!/usr/bin/env python
"""
python lib/get_cve.py \
    tenant \
    --git https://gitlab.cee.redhat.com/gnecasov/container-errata-templates.git \
    --branch main \

    git clone https://github.com/openshift/contra-lib.git --branch master --depth 1 "/tmp/1"

"""

import argparse
import os
import tempfile
import re
import subprocess

pattern = r'(CVE-\d+-\d+)'


def find_cve():
    parser = argparse.ArgumentParser()
    parser.add_argument(
            "mode",
            choices=["managed", "tenant"],
            help="Mode in which the script is called. It does not have any impact for this script.")
    parser.add_argument("--git", required=True, help="SSH clone string for a git repository")
    parser.add_argument("--branch", required=True, help="Branch name to be cloned, it can be a branch or a SHA.")
    parser.add_argument("--reference-branch", required=False, help="Branch name to be cloned, it can be a branch or a SHA.")
    args = vars(parser.parse_args())
    return git_log_titles(args['git'], args['branch'], args['reference_branch'])


def git_log_titles(git_url, branch, reference_branch):
    tmpdir = tempfile.mkdtemp()
    git_cmd = ["git", "clone", git_url, "--branch", branch, tmpdir]
    result = subprocess.run(git_cmd, check=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Something went wrong cloning, details below:")
        print(f"Command: '{' '.join(git_cmd)}'")
        print(f"Stdout: '{result.stdout}'")
        print(f"Stderr: '{result.stderr}'")
        exit(result.returncode)
    
    os.chdir(tmpdir)
    SEPARATOR='---------------'
    
    if reference_branch:
      git_cmd = ["git", "checkout", reference_branch]
      result = subprocess.run(git_cmd, check=True, capture_output=True, text=True)
      if result.returncode != 0:
          print("Something went wrong getting reference branch, details below:")
          print(f"Command: '{' '.join(git_cmd)}'")
          print(f"Stdout: '{result.stdout}'")
          print(f"Stderr: '{result.stderr}'")
          exit(result.returncode)
      git_cmd = ["git", "log", f"{reference_branch}..{branch}",f"--pretty=format:%B{SEPARATOR}"]
    else:
      git_cmd = ["git", "log", f"{branch}",f"--pretty=format:%B{SEPARATOR}"]

    result = subprocess.run(git_cmd, check=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Something went wrong cloning, details below:")
        print(f"Command: '{' '.join(git_cmd)}'")
        print(f"Stdout: '{result.stdout}'")
        print(f"Stderr: '{result.stderr}'")
        exit(result.returncode)
    list_of_commits = result.stdout.split(SEPARATOR)
    commits_with_cves = find_logs(list_of_commits)
    return get_cves(commits_with_cves)


def find_logs(commits):
    matching_commits = []
    for message in commits:
        if re.search(pattern, message):
            matching_commits.append(message)
    return matching_commits

def get_cves(commits):
  all_cves = []
  for message in commits:
    cves = re.findall(pattern, message)
    for cve in cves:
      all_cves.append(cve)
  return all_cves 

if __name__ == "__main__":
    print(find_cve())
