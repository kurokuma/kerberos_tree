# -*- coding: utf-8 -*-
import sys
import os
from datetime import datetime
import argparse

try:
    import Evtx.Evtx as evtx
except ImportError as e:
    print("pip install python-evtx")
    exit(1)

try:
    import xmltodict
except ImportError as e:
    print("pip install xmltodict")
    exit(1)

def exclusion_name(target_user_name):
    ex_flag = False
    for _ in ["$", "SYSTEM", "DWM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"]:
        if _ in target_user_name:
            ex_flag = True
    return ex_flag

def main(file_path):
    if not os.path.exists(file_path):
        print("[x]", "No such file ->", file_path)
        return

    with evtx.Evtx(file_path) as f:
        for record in f.records():
            # print(xmltodict.parse(record.xml()))
            event_dict = xmltodict.parse(record.xml())
            event_id = event_dict["Event"]["System"]["EventID"]["#text"]
            time_created = event_dict["Event"]["System"]["TimeCreated"]["@SystemTime"]

            if event_id == "4768":
                target_domain_name = event_dict["Event"]["EventData"]["Data"][1]["#text"]
                target_user_name = event_dict["Event"]["EventData"]["Data"][0]["#text"]
                target_sid = event_dict["Event"]["EventData"]["Data"][2]["#text"]
                service_sid = event_dict["Event"]["EventData"]["Data"][4]["#text"]
                if exclusion_name(target_user_name): continue
                print("[+] {time_created}:|--{event_id}--{target_user_name}({service_sid})({target_sid})".format(
                    time_created=time_created.split(".")[0], event_id=event_id, target_user_name=target_user_name,
                    service_sid=service_sid, target_sid=target_sid
                ))

            if event_id == "4769":
                target_user_name = event_dict["Event"]["EventData"]["Data"][0]["#text"]
                target_domain_name = event_dict["Event"]["EventData"]["Data"][1]["#text"]
                service_sid = event_dict["Event"]["EventData"]["Data"][3]["#text"]
                logon_guid = event_dict["Event"]["EventData"]["Data"][9]["#text"]
                if exclusion_name(target_user_name): continue
                print("[!] {time_created}:    \____{event_id}----{target_user_name}({service_sid})----{logon_guid}".format(
                    time_created=time_created.split(".")[0],event_id=event_id, target_user_name=target_user_name,
                    service_sid=service_sid, logon_guid=logon_guid
                ))

            if event_id == "4624":
                target_user_name = event_dict["Event"]["EventData"]["Data"][5]["#text"]
                target_domain_name = event_dict["Event"]["EventData"]["Data"][6]["#text"]
                target_user_sid = event_dict["Event"]["EventData"]["Data"][4]["#text"]
                logon_guid = event_dict["Event"]["EventData"]["Data"][12]["#text"]
                if exclusion_name(target_user_name): continue
                print("[-] {time_created}:          \____{event_id}----{target_user_name}@{target_domain_name}({target_user_sid})----{logon_guid}".format(
                    time_created=time_created.split(".")[0], event_id=event_id, target_user_name=target_user_name, target_domain_name=target_domain_name,
                    target_user_sid=target_user_sid, logon_guid=logon_guid
                ))

            if event_id == "4648":
                target_user_name = event_dict["Event"]["EventData"]["Data"][5]["#text"]
                target_domain_name = event_dict["Event"]["EventData"]["Data"][6]["#text"]
                target_logon_guid = event_dict["Event"]["EventData"]["Data"][7]["#text"]
                if exclusion_name(target_user_name): continue
                print("[-] {time_created}:          \____{event_id}----{target_user_name}@{target_domain_name}--{target_logon_guid}".format(
                    time_created=time_created.split(".")[0], event_id=event_id, target_user_name=target_user_name, target_domain_name=target_domain_name,
                    target_logon_guid=target_logon_guid
                ))

            if event_id == "4672":
                target_user_name = event_dict["Event"]["EventData"]["Data"][1]["#text"]
                target_domain_name = event_dict["Event"]["EventData"]["Data"][2]["#text"]
                target_user_sid = event_dict["Event"]["EventData"]["Data"][0]["#text"]
                if exclusion_name(target_user_name): continue
                print("[-] {time_created}:          \____{event_id}----{target_user_name}@{target_domain_name}--{target_user_sid}".format(
                    time_created=time_created.split(".")[0], event_id=event_id, target_user_name=target_user_name, target_domain_name=target_domain_name,
                    target_user_sid=target_user_sid
                ))

if __name__ == '__main__':
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print("python", sys.argv[0], "AD's Security Eventlog")