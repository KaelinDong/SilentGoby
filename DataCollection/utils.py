import os
import re
import json
import time
import requests
import subprocess
import xml.etree.ElementTree as ET

import cve_searchsploit as CS
from tqdm import tqdm

HEADERS_NVD_ACCESS = {'Authorization': os.getenv("NVD_API_KEY")}
URL_CPE_ACCESS_CVE = url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}&startIndex={}"


"""
    CVE vulnerability collection.
"""

def read_cpe_xml(str_path_file: str = "./assets/official-cpe-dictionary_v2.3.xml") -> dict:
    """
    This funciton is to read all the CPE information from the given xml file.
    :param str_path_file: downloaded cpe summarization file from NVD
    :return:
    """
    file_xml = open(str_path_file, "r")
    str_xml = file_xml.read()
    file_xml.close()

    # resolve the content
    tree = ET.ElementTree(file = str_path_file)
    root = tree.getroot()

    dict_namespace = {
        'cpe': 'http://cpe.mitre.org/dictionary/2.0',
        'cpe-23': 'http://scap.nist.gov/schema/cpe-extension/2.3',
    }

    cpe_items = root.findall('cpe:cpe-item', dict_namespace)

    dict_all_cpe_version = {}

    # set the common cpe

    for item in cpe_items:
        cpe23_item = item.find("cpe-23:cpe23-item", dict_namespace)

        if cpe23_item is not None:
            str_cpe_name = cpe23_item.get("name")
            list_cpe_components = str_cpe_name.split(":")

            list_cpe_components[5] = "-"

            str_cpe_name_no_version = ":".join(list_cpe_components)

            if str_cpe_name_no_version in dict_all_cpe_version.keys():
                dict_all_cpe_version[str_cpe_name_no_version].append(str_cpe_name)
            else:
                dict_all_cpe_version[str_cpe_name_no_version] = [str_cpe_name]

    for key in dict_all_cpe_version.keys():
        list_key_components = key.split(":")

        # set the common name of star
        list_key_components[5] = "*"
        str_key_common_star = ":".join(list_key_components)

        # set the common name of bar
        list_key_components[5] = "-"
        str_key_common_bar = ":".join(list_key_components)

        if str_key_common_star not in dict_all_cpe_version[key]:
            dict_all_cpe_version[key].append(str_key_common_star)
        if str_key_common_bar not in dict_all_cpe_version[key]:
            dict_all_cpe_version[key].append(str_key_common_bar)

    return dict_all_cpe_version


def retrieve_cpe_version(str_target_cpe: str, dict_all_cpe_version: dict) -> list:
    """
    This funciton is to retrieve all the CPE versions regarding the given CPE (*)
    :param str_cpe: CPE string
    :param dict_all_cpe_version: dictionary containing all the CPE versions regarding all products
    :return: list of all corresponded CPE versions
    """
    list_str_cpe = dict_all_cpe_version[str_target_cpe]

    return list_str_cpe


def access_cve_through_cpe(str_cpe: str) -> list:
    """
    This funciton is to access all the CVEs related to the target CPE
    :param str_cpe: CPE string
    :return: list of all corresponded CVEs
    """
    list_dict_cve = []

    index_start = 0
    while True:
        response = requests.get(
            URL_CPE_ACCESS_CVE.format(str_cpe, index_start),
            headers = HEADERS_NVD_ACCESS
        )

        if response.status_code == 200:
            # try:
            data = response.json()
            list_current_page_cve = data["vulnerabilities"]
            list_dict_cve.extend(list_current_page_cve)

            if len(list_current_page_cve) == 0:
                break

            index_start += data["resultsPerPage"]

        else:
            break

        time.sleep(2)


    return list_dict_cve


"""
    Vulnerability exploit collection.
"""

def exp_collection_from_exploitdb(str_cve_detail_json: str):
    """
    This funciton is to available exploits from exploitdb database
    :param str_cve_detail_json: the file including collected CVEs
    """
    # read list of target CVEs
    file_json = open(str_cve_detail_json, "r", encoding = "utf-8")
    dict_cve_details = json.load(file_json)
    file_json.close()

    # template url setting
    str_exploitdb_url = "https://www.exploit-db.com/exploits/{}"

    n_exploitdb_ref = 0

    for key in tqdm(dict_cve_details.keys()):
        str_cve = key

        result = CS.edbid_from_cve(str_cve)

        list_exp_url = []
        if result != []:
            for exp_id in result:
                list_exp_url.append(str_exploitdb_url.format(exp_id))

            n_exploitdb_ref += 1


        print(list_exp_url)

    # you can save the result to specific file
    # return xxx


def exp_collection_from_metasploit(str_cve_detail_json):
    """
        This function is to available exploits from metasploit database
        :param str_cve_detail_json: the file including collected CVEs
        """
    # read list of target CVEs
    file_json = open(str_cve_detail_json, "r", encoding="utf-8")
    dict_cve_details = json.load(file_json)
    file_json.close()

    for key in tqdm(dict_cve_details.keys()):
        str_cve = key
        # The Metasploit command to search for the CVE
        command = f'msfconsole -q -x "search cve:{str_cve}; exit"'

        # Run the command and capture the output
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode()

        # Remove ANSI escape sequences (control characters)
        output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', output)


        # Check if results were found, if there are results, save them to a file
        if "No results from search" not in output:
            print(output)
        else:
            print(f"No results for {str_cve}, skipping...")