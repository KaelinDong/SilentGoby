import os
import json
import sys

import requests
from datetime import datetime
from lxml import etree, html
from bs4 import BeautifulSoup
from tqdm import tqdm
from collections import Counter


"""
    Exploit available time analysis.
"""


def fetch_metasploitbtime_by_commit(str_exploit_url: str) -> str:
    """
    This function is to resolve exploit available time of metasploit-provided exploits
    :param str_exploit_url: exploit url
    :return: available time in string
    """
    list_parts = str_exploit_url.split("/blob/master//")
    str_repo = list_parts[0].replace("https://github.com/", "")
    str_resource = list_parts[1]

    url = f"https://api.github.com/repos/{str_repo}/commits"
    params = {"path": str_resource}
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {os.getenv('GITHUB_TOKEN')}",
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        commits = response.json()

        commit_dates = [commit["commit"]["author"]["date"] for commit in commits]

        str_available_time = commit_dates[-1]
        return str_available_time
    except Exception as e:
        print(f"Exception：{e}")
        return None


def fetch_exploitdbtime_by_xpath(
        url,
        xpath = "/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[3]/div/div[1]/div/div/div/div[2]/h6/text()"
):
    """
    This function is to resolve exploit available time of exploitdb-provided exploits
    :param str_exploit_url: exploit url
    :param xpath: xpath expression
    :return: available time in string
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        tree = etree.HTML(response.text)
        elements = tree.xpath(xpath)

        str_time = elements[0].replace("\n", "").strip()
        date_with_time = f"{str_time}T23:59:59Z"
        return date_with_time

    except requests.exceptions.RequestException as e:
        return f"An error occurred while fetching the URL: {e}"
    except Exception as e:
        return f"An error occurred: {e}"


def fetch_githubblobexptime_by_commit(str_exploit_url: str) -> str:
    """
    This function is to resolve exploit available time of GitHub blob-based exploits
    :param str_exploit_url: exploit url
    :return: available time in string
    """
    list_parts = str_exploit_url.split("/blob/master/")
    str_repo = list_parts[0].replace("https://github.com/", "")
    str_resource = list_parts[1]

    url = f"https://api.github.com/repos/{str_repo}/commits"
    params = {"path": str_resource}
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {os.getenv('GITHUB_TOKEN')}",
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        commits = response.json()

        commit_dates = [commit["commit"]["author"]["date"] for commit in commits]

        str_available_time = commit_dates[-1]
        return str_available_time
    except Exception as e:
        print(f"Exception：{e}")
        return None


def fetch_tfblobexptime_by_commit(str_exploit_url: str) -> str:
    """
    This function is to resolve exploit available time of Tensorflow exploits
    :param str_exploit_url: exploit url
    :return: available time in string
    """
    list_parts = str_exploit_url.split("/blob/")
    str_repo = list_parts[0].replace("https://github.com/", "")
    str_resource = list_parts[1].split("#")[0]

    str_commit, str_resource = str_resource.split("/", 1)

    url = f"https://api.github.com/repos/{str_repo}/commits"

    params = {
        "path": str_resource,
        "sha": str_commit
    }
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {os.getenv('GITHUB_TOKEN')}",
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        commits = response.json()

        commit_dates = [commit["commit"]["author"]["date"] for commit in commits]

        str_available_time = commit_dates[-1]
        return str_available_time
    except Exception as e:
        print(f"Exception：{e}")
        return None


def fetch_githubissueexptime_by_commit(issue_url: str) -> str:
    """
    This function is to resolve exploit available time of GitHub issue-based exploits
    :param str_exploit_url: exploit url
    :return: available time in string
    """
    repo_parts = issue_url.replace("https://github.com/", "").split("/issues/")
    str_repo = repo_parts[0]
    issue_number = repo_parts[1]

    api_url = f"https://api.github.com/repos/{str_repo}/issues/{issue_number}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {os.getenv('GITHUB_TOKEN')}",
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        issue_data = response.json()

        created_at = issue_data.get("created_at", None)
        if created_at:
            return created_at
        else:
            return None

    except Exception as e:
        print(f"Exception: {e}")
        return None


def fetch_githubadvisoryexptime_by_url(str_advisory_url):
    """
        This function is to resolve exploit available time of GitHub advisory-based exploits
        :param str_exploit_url: exploit url
        :return: available time in string
        """
    try:
        response = requests.get(str_advisory_url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            publish_time_element = soup.find('relative-time')
            if publish_time_element:
                return publish_time_element['datetime']
            else:
                print("No publish time provided.")
                return None
        else:
            print(f"Error，status code：{response.status_code}")
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def fetch_phpexptimeby_url(url, xpath = "//*[@id='submission']/td[1]") -> str:
    """
        This function is to resolve exploit available time of php exploits
        :param str_exploit_url: exploit url
        :return: available time in string
        """
    try:
        response = requests.get(url)

        if response.status_code == 200:
            tree = html.fromstring(response.content)
            element = tree.xpath(xpath)
            if element:
                str_time = element[0].text_content().strip()

                dt = datetime.datetime.strptime(str_time, "%Y-%m-%d %H:%M %Z")
                str_formatted_time = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                return str_formatted_time

                return str_time
            else:
                print("No target elements.")
                return None
        else:
            print(f"Error, status code：{response.status_code}")
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def calculate_days_difference(str_disclosure_time: str, str_patch_time: str):
    """
    This function is to calculate the number of internal days between two given time
    :param str_disclosure_time: in our study, this is the vulnerability disclosure time
    :param str_patch_time: in our study, this is the patch commit time
    :return:
    """
    # convert str_time to datetime_time
    time_disclosure = datetime.strptime(str_disclosure_time[:-1], "%Y-%m-%dT%H:%M:%S")
    time_patch = datetime.strptime(str_patch_time[:-1], "%Y-%m-%dT%H:%M:%S")

    # calculate the timeframe and convert the result to days
    n_day_gap = (time_disclosure - time_patch).days

    return n_day_gap

"""
    Analyzing the Silent Vulnerability Distribution
"""
def ana_silent_vulnerability_distribution(str_json_cve_details: str):
    file_json = open(str_json_cve_details, "r", encoding="utf-8")
    dict_cve_details = json.load(file_json)
    file_json.close()

    n_silent_vulnerability = 0
    list_str_repo = []

    for str_cve, dict_cve in dict_cve_details.items():
        str_disclosure_time = dict_cve["str_disclosure_time"]
        str_patch_time = dict_cve["patch_time"]

        n_day_gap = calculate_days_difference(str_disclosure_time, str_patch_time)

        str_patch_commit = dict_cve["patch_commit"]

        from urllib.parse import urlparse

        str_repo = ""
        parsed_url = urlparse(str_patch_commit)
        if parsed_url.netloc == "github.com":
            path_parts = parsed_url.path.strip("/").split("/")
            if len(path_parts) >= 2:
                str_repo = f"https://{parsed_url.netloc}/{path_parts[0]}/{path_parts[1]}"

        if n_day_gap >= 7:
            n_silent_vulnerability += 1
            list_str_repo.append(str_repo)

    print(f"Sum number of silent vulnerability: {n_silent_vulnerability} & {len(list_str_repo)}\n")

    print(f"Silent vulnerability distribution across OSS:")
    from collections import Counter
    dict_count = dict(Counter(list_str_repo))

    for key, value in dict_count.items():
        print(f"{key}: {value}\n")


"""
    Analyzing the VEW distribution in OSS perspective.
"""

def ana_vew_across_severity(
        n_day_target: int,
        str_severity_target: str,
        str_json_cve_details: str = "../Dataset/formatted_dataset.json"
):
    """
    This function is to analyze the VEW distribution across silent vulnerability fix, considering severity.
    This function corresponds to the result of Table 2.
    :param n_day_target:
    :param str_severity_target:
    :param str_json_cve_details:
    :return:
    """
    file_json = open(str_json_cve_details, "r", encoding='utf-8')
    dict_cve_details = json.load(file_json)
    file_json.close()

    n_target = 0

    for str_cve, dict_cve in dict_cve_details.items():
        str_severity = dict_cve["str_severity"]

        n_diff_day = calculate_days_difference(dict_cve["str_disclosure_time"], dict_cve["patch_time"])

        if n_diff_day >= n_day_target and str_severity == str_severity_target:
            n_target += 1

    print(n_target)


def ana_vew_across_cwe(
        n_day_target: int,
        str_json_cve_details: str = "../Dataset/formatted_dataset.json"
):
    """
    This function is to calculate the VEW distribution across CWE.
    This function corresponds to the result of Table 3.
    :param n_day_target: target diff days for the analysis
    :param str_json_cve_details: the json file of the collected CVEs
    """
    file_json = open(str_json_cve_details, "r", encoding='utf-8')
    dict_cve_details = json.load(file_json)
    file_json.close()

    dict_cwe_vew = {}

    for str_cve, dict_cve in dict_cve_details.items():
        str_cwe = dict_cve["list_str_cwe"][0] if type(dict_cve["list_str_cwe"]) == list else dict_cve["list_str_cwe"]
        n_diff_day = calculate_days_difference(dict_cve["str_disclosure_time"], dict_cve["patch_time"])

        if n_diff_day >= n_day_target:
            if str_cwe not in dict_cwe_vew.keys():
                dict_cwe_vew[str_cwe] = {
                    "list_str_cve": [],
                    "list_n_days": []
                }

                dict_cwe_vew[str_cwe]["list_str_cve"].append(str_cve)
                dict_cwe_vew[str_cwe]["list_n_days"].append(n_diff_day)

            else:
                dict_cwe_vew[str_cwe]["list_str_cve"].append(str_cve)
                dict_cwe_vew[str_cwe]["list_n_days"].append(n_diff_day)

    for key, value in sorted(dict_cwe_vew.items(), key=lambda item: len(item[1]["list_str_cve"]), reverse=True):
        print(f"CWE: {key}, #Silent fixes: {len(value['list_str_cve'])}")


"""
    Analyzing the distribution exploit availablility in VEWs
"""
def ana_exploit_available_time(str_json_file: str = "../Dataset/formatted_dataset.json"):
    """
    This function is to analyze the VEW availability in VEWs, corresponding to Table 5.
    :param str_json_file: file path of the collected CVEs
    """
    file_json = open(str_json_file, "r", encoding="utf-8")
    dict_data = json.load(file_json)
    file_json.close()

    # extract the earliest available time of exploit
    list_over_15_severity, list_over_30_severity, list_over_60_severity, list_over_90_severity, list_over_365_severity = [], [], [], [], []

    for str_cve, dict_cve_detail in tqdm(dict_data.items(), desc = "Time gap analysis"):
        list_exp_ava_time = []

        # add the available time of NVD-provided exploits
        for exp_nvd_ref in dict_cve_detail["list_str_ref"]:
            list_exp_ava_time.append(exp_nvd_ref[1])

        # add the available time of ExploitDB-provided exploits
        for exp_exploitdb_ref in dict_cve_detail["exploitdb_ref"]:
            list_exp_ava_time.append(exp_exploitdb_ref[1])

        # add the available time of metasploit-provided exploits
        for exp_metasploit_ref in dict_cve_detail["metasploit_ref"]:
            list_exp_ava_time.append(exp_metasploit_ref[1])

        if len(list_exp_ava_time) == 0:
            continue

        try:
            dt_exp = min(datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ") for t in list_exp_ava_time)
        except:
            print(str_cve)
            print(list_exp_ava_time)
            sys.exit()

        # extract the fixed time of the vulnerability
        str_fix_time = dict_cve_detail["patch_time"]

        # extract the disclosure time of the vulnerability
        str_disclosure_time = dict_cve_detail["str_disclosure_time"]

        # comparing which one is later among the exploit available time and the fix time
        dt_fix = datetime.strptime(str_fix_time, "%Y-%m-%dT%H:%M:%SZ")
        dt_disclosure = datetime.strptime(str_disclosure_time, "%Y-%m-%dT%H:%M:%SZ")

        if dt_exp > dt_fix:
            # the exp available time is later, using this time to calculate the gap
            time_gap = dt_disclosure - dt_exp
            n_day_gap = time_gap.days
        else:
            # the fix time is later, using this time to calculate the gap
            time_gap = dt_disclosure - dt_fix
            n_day_gap = time_gap.days

        if n_day_gap >= 15:
            list_over_15_severity.append(dict_cve_detail["str_severity"])
        if n_day_gap >= 30:
            list_over_30_severity.append(dict_cve_detail["str_severity"])
        if n_day_gap >= 60:
            list_over_60_severity.append(dict_cve_detail["str_severity"])
        if n_day_gap >= 90:
            list_over_90_severity.append(dict_cve_detail["str_severity"])
        if n_day_gap >= 365:
            list_over_365_severity.append(dict_cve_detail["str_severity"])

    print("Number of exploits:")
    print("over 15: {}, over 30: {}, over 60: {}, over 90: {}, over 365: {}".format(len(list_over_15_severity), len(list_over_30_severity), len(list_over_60_severity), len(list_over_90_severity), len(list_over_365_severity)))

    print()

    print("Over 15 distribution:")
    print(Counter(list_over_15_severity))

    print("Over 60 distribution:")
    print(Counter(list_over_60_severity))

    print("Over 30 distribution:")
    print(Counter(list_over_30_severity))

    print("Over 90 distribution:")
    print(Counter(list_over_90_severity))

    print("Over 365 distribution:")
    print(Counter(list_over_365_severity))

# ana_silent_vulnerability_distribution("../Dataset/cleaned_final_results.json")