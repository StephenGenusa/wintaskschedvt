import datetime
import hashlib
import os
import re
import time

from virustotal_python.virustotal import Virustotal, VirustotalError
import win32api  # python venv\Scripts\pywin32_postinstall.py -install
import win32com.client


def find_executable_path(exe_filename) -> str:
    """
    Use the Win32 API call FindExecutable to locate an executable listed as a task scheduler action but
    has no explicit directory
    :param exe_filename:
    :return: full path to executable
    """
    try:
        ret_value = win32api.FindExecutable(exe_filename, None)
        return ret_value[1]
    except:
        return exe_filename


def clean_env_vars(executable_path) -> str:
    """
    Substitutes env variables like %windir% for the literal paths
    :param an executable_path that may have an env variable:
    :return: literal path to executable
    """
    search_res = re.search("%.*?%", executable_path, re.IGNORECASE)
    if search_res:
        escaped_env_var = search_res.group(0)
        env_var = escaped_env_var.replace("%", "")
        env_value = os.getenv(env_var)
        return executable_path.replace(escaped_env_var, env_value)
    else:
        return executable_path


def parse_for_executable_path(possible_executable) -> str:
    """
    Search task scheduler action value for executable file and make sure full path is attached
    :param possible_executable:
    :return:
    """
    base_executable_item = re.search(
        r"([A-Z]:.*\.(bat|bin|cmd|com|cpl|dll|ex_|exe|gadget|inf1|ins|inx|isu|job|js|jse|lnk|msc|msi|msp|"
        + "mst|paf|pif|ps1|reg|rgs|scr|sct|shb|shs|u3p|vb|vbe|vbs|vbscript|ws|wsf|wsh))",
        clean_env_vars(possible_executable),
        re.IGNORECASE,
    )
    if base_executable_item:
        if not os.path.dirname(base_executable_item.group(0)):
            return find_executable_path(base_executable_item.group(0))
        else:
            return base_executable_item.group(0)


def get_task_scheduler_executables() -> list:
    """
    Build a list of executables from all Task Scheduler event actions including parameters that have DLLs
    :return: list of all primary and secondary executables
    """
    scheduler = win32com.client.Dispatch("Schedule.Service")
    scheduler.Connect()
    task_folders = [scheduler.GetFolder("\\")]
    task_scheduler_executable_list = []
    while task_folders:
        task_folder = task_folders.pop(0)
        task_folders += list(task_folder.GetFolders(0))
        tasks = list(task_folder.GetTasks(1))  # TASK_ENUM_HIDDEN = 1
        for task in tasks:
            actions = task.Definition.Actions
            for action in actions:
                if hasattr(action, "Path"):
                    for binary_path in [action.Path, action.Arguments]:
                        binary_path = parse_for_executable_path(binary_path)
                        if (
                            binary_path
                            and binary_path not in task_scheduler_executable_list
                        ):
                            task_scheduler_executable_list.append(binary_path)
    return task_scheduler_executable_list


def get_sha256(binary_filename) -> str:
    """
    Get sha-256 hash for a file
    :param binary_filename:
    :return: sha-256 hash
    """
    with open(binary_filename, "rb") as fp:
        bytes = fp.read()
        return hashlib.sha256(bytes).hexdigest()


def submit_sample_to_virus_total(virus_total, binary_path) -> None:
    """
    Submit a file for analysis
    :param virus_total:
    :param binary_path:
    :return:
    """
    files = {
        "file": (
            os.path.basename(binary_path),
            open(os.path.abspath(binary_path), "rb"),
        )
    }
    virus_total.request("files", files=files, method="POST")
    print(f"File {binary_path} submitted. Waiting for analysis")
    time.sleep(90)


def check_virustotal(virus_total, binary_path) -> None:
    """
    Check a file's hash against VT and if it hasn't been seen before, submit it for analysis
    :param virus_total:
    :param binary_path:
    :return:
    """
    try:
        resp = virus_total.request(f"files/{get_sha256(binary_path)}")
    except VirustotalError as exc:
        if exc.error()['code'] == 'NotFoundError':
            submit_sample_to_virus_total(virus_total, binary_path)
            check_virustotal(virus_total, binary_path)
    if "attributes" in resp.data:
        print(
            str(resp.data["attributes"]["last_analysis_stats"]["suspicious"]).rjust(3)
            + str(resp.data["attributes"]["last_analysis_stats"]["malicious"]).rjust(5)
            + str(resp.data["attributes"]["last_analysis_stats"]["undetected"]).rjust(12) + "  "
            + datetime.datetime.fromtimestamp(resp.data["attributes"]["first_submission_date"]).strftime("%m/%d/%y")
            + "   "
            + datetime.datetime.fromtimestamp(resp.data["attributes"]["last_analysis_date"]).strftime("%m/%d/%y")
            + "  "
            + binary_path
        )
        time.sleep(1)


def test_binaries_against_virus_total(binary_list) -> None:
    """
    Run a list of executables against VirusTotal displaying results
    :param binary_list:
    :return: None
    """
    print("Sus  Mal  Undetected     First       Last  Binary")
    #        0    0          67  04/06/20   12/30/21
    vtotal = Virustotal(API_KEY=os.getenv("VIRUSTOTAL_API_KEY"), API_VERSION="v3")
    for binary_path in binary_list:
        if os.path.isfile(binary_path):
            check_virustotal(vtotal, binary_path)
        else:
            print(f"Warning! File not found: {binary_path}")


def main():
    test_binaries_against_virus_total(get_task_scheduler_executables())


if __name__ == "__main__":
    main()
