import os
import time
import requests


HEADERS_GITHUB_API_ACCESS = {
    'Authorization': f'token {os.getenv("GITHUB_TOKEN")}',
    'Accept': 'application/vnd.github.v3+json'
}

URL_COMMIT_DATA = "https://api.github.com/repos/{}/{}/commits/{}"
URL_PATCH_FILE = "https://api.github.com/repos/{}/{}/contents/{}?ref={}"

PATH_FOLDER_PATCH_FILES = os.path.join(os.getcwd(), "datasets", "codechanges_downstream")
print(PATH_FOLDER_PATCH_FILES)


def read_patch_commit(str_auto_commit: str) -> (list, str):
    # initialize the return value
    list_patch_commit = []

    # read all commits
    list_patch_commit.extend(read_txt_file(str_auto_commit))
    list_result = [patch_commit for patch_commit in list_patch_commit if patch_commit.strip() != ""]

    return list_result


def read_txt_file(str_txt_file: str) -> list:
    """
        This function is to read a txt file and return a list of string variables, each string relates to one line in file.

        Input:
            1. str - path of the txt file

        Output:
            1. list - list of the lines in the txt file
    """
    list_line = []

    file_txt = open(str_txt_file, "r")

    for line in file_txt:
        list_line.append(line)

    file_txt.close()

    return list_line


def get_commit_changes(str_vendor, str_product, str_patch_commit):
    url_commit_data = URL_COMMIT_DATA.format(str_vendor, str_product, str_patch_commit)

    response = requests.get(
        url_commit_data,
        headers = HEADERS_GITHUB_API_ACCESS
    )

    if response.status_code == 200:
        dict_commit_data = response.json()
        list_changed_files = dict_commit_data["files"]
        list_str_file = [file["filename"] for file in list_changed_files]
        str_parent_commit = dict_commit_data['parents'][0]['sha'] if dict_commit_data['parents'] else None

        return list_str_file, str_parent_commit

    else:
        return [], ""


def crawl_patch_file(owner, repo, list_str_change_files, commit_sha) -> list:
    list_str_file_content = []

    for path in list_str_change_files:
        # construct url and send request
        url = URL_PATCH_FILE.format(owner, repo, path, commit_sha)
        response = requests.get(url, headers=HEADERS_GITHUB_API_ACCESS)

        # check response status
        # if response.status_code == 200:
        file_data = response.json()
        download_url = file_data.get('download_url')

        # parse response
        str_file_content = ""
        if download_url:
            file_content_response = requests.get(download_url)
            str_file_content = file_content_response.text


        list_str_file_content.append(str_file_content)

    return list_str_file_content


def save_patch_file(str_file_content: str, str_save_path: str) -> None:
    """
        This function is to save the crawled str file content into local file.

        Input:
            TBD ...

        Output:
            TBD ...
    """
    with open(str_save_path, "w", encoding="utf-8") as file:
        file.write(str_file_content)


def main():

    # traverse all CVEs and patches
    list_str_cve = [
        "CVE-2012-5360",
        "CVE-2014-4610",
        "CVE-2013-4535"
    ]
    list_str_patch = [
        "https://github.com/ffmpeg/ffmpeg/commit/72ec043af4510723c53c729a67be482a14b7c7f3",
        "https://github.com/ffmpeg/ffmpeg/commit/d6af26c55c1ea30f85a7d9edbc373f53be1743ee",
        "https://github.com/qemu/qemu/commit/36cf2a37132c7f01fa9adb5f95f5312b27742fd4"
    ]

    # for key, value in tqdm(dict_cve_detail.items(), desc="Processing CVE details"):
    for str_cve_id, str_commit_url in zip(list_str_cve, list_str_patch):
        # read log file
        # with open("./datasets/code_changes/log.txt", "r", encoding="utf-8") as file:
        #     lines = file.readlines()

        # lines = [line.strip() for line in lines]


        # str_cve_id = key
        # str_commit_url = value["patch_commit"]

        # if str_cve_id in lines:
        #     continue

        str_vendor, str_product, str_patch_commit = str_commit_url.split("/")[3].strip(), str_commit_url.split("/")[
            4].strip(), str_commit_url.split("/")[-1].strip()
        str_vendor, str_product = str_vendor.lower(), str_product.lower()

        # get changed files
        list_str_change_file, str_parent_commit = get_commit_changes(str_vendor, str_product, str_patch_commit)
        list_str_file_content_before = crawl_patch_file(str_vendor, str_product, list_str_change_file, str_parent_commit)
        list_str_file_content_after = crawl_patch_file(str_vendor, str_product, list_str_change_file, str_patch_commit)

        # determine whether the library has been accessed; if not, make the dir
        str_folder_file_patch_before = os.path.join(PATH_FOLDER_PATCH_FILES, f"{str_vendor}_{str_product}", str_cve_id,
                                                    "patch_before")

        str_folder_file_patch_after = os.path.join(PATH_FOLDER_PATCH_FILES, f"{str_vendor}_{str_product}", str_cve_id,
                                                    "patch_after")

        if not os.path.exists(str_folder_file_patch_before):
            os.makedirs(str_folder_file_patch_before)
        if not os.path.exists(str_folder_file_patch_after):
            os.makedirs(str_folder_file_patch_after)

        # save the results into the target folder
        for str_file_content, str_file_path in zip(list_str_file_content_before, list_str_change_file):
            save_patch_file(str_file_content,
                            os.path.join(str_folder_file_patch_before, str_file_path.split("/")[-1]))

        for str_file_content, str_file_path in zip(list_str_file_content_after, list_str_change_file):
            save_patch_file(str_file_content,
                            os.path.join(str_folder_file_patch_after, str_file_path.split("/")[-1]))

        # write the crawled CVE into log
        with open("./datasets/code_changes/log.txt", "a", encoding="utf-8") as file:
            file.write(f"{str_cve_id}\n")

        time.sleep(5)



if __name__ == "__main__":
    main()
