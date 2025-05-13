import json

from utils import (
    fetch_exploitdbtime_by_xpath,
    fetch_githubadvisoryexptime_by_url,
    fetch_githubissueexptime_by_commit,
    fetch_phpexptimeby_url,
    fetch_tfblobexptime_by_commit,
    fetch_githubblobexptime_by_commit,
    fetch_metasploitbtime_by_commit,
    ana_vew_across_severity,
    ana_vew_across_cwe,
    ana_exploit_available_time,
    calculate_days_difference
)



if __name__ == '__main__':
    # str_json_path = "../Dataset/cleaned_final_results_exp.json"
    #
    # file_json = open(str_json_path, "r", encoding="utf-8")
    # dict_data = json.load(file_json)
    # file_json.close()
    #
    # list_str_cwe = []
    # for key, value in dict_data.items():
    #     str_disclosure_time = value["str_disclosure_time"]
    #     str_patch_time = value["patch_time"]
    #
    #     n_gap_days = calculate_days_difference(str_disclosure_time, str_patch_time)
    #
    #     if n_gap_days >= 7:
    #         str_cwe = value["list_str_cwe"][0] if type(value["list_str_cwe"]) == list else value["list_str_cwe"]
    #         list_str_cwe.append(str_cwe)
    #
    # from collections import Counter
    # print(Counter(list_str_cwe))
    # print(len(list_str_cwe))


    # test case for resolving exploit available time
    # print(fetch_metasploitbtime_by_commit("https://github.com/rapid7/metasploit-framework/blob/master//modules/auxiliary/dos/ssl/dtls_fragment_overflow.rb"))


    # test case for silent vulnerability fix analysis
    # ana_vew_across_severity(
    #     365,
    #     "LOW",
    #     "../Dataset/cleaned_final_results.json"
    # )

    # ana_vew_across_cwe(
    #     365,
    #     str_json_cve_details = "../Dataset/cleaned_final_results_exp.json"
    # )

    ana_exploit_available_time(str_json_file = "../Dataset/cleaned_final_results_exp.json")