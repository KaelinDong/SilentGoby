from utils import (
    read_cpe_xml,
    retrieve_cpe_version,
    access_cve_through_cpe,
    exp_collection_from_exploitdb,
    exp_collection_from_metasploit
)

import json


if __name__ == "__main__":
    str_json_path = "../Dataset/formatted_dataset.json"

    # test case for collecting CVE vulnerabilities
    # list_cve = access_cve_through_cpe("cpe:2.3:a:php:php:0.1:*:*:*:*:*:*:*")

    # test case for collecting exploit from exploitdb
    # exp_collection_from_exploitdb(str_json_path)

    # test case for collecting exploit from metasploit
    # exp_collection_from_metasploit(str_json_path)
