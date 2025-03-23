import requests
from urllib.parse import urlsplit
from urllib.parse import urlunsplit
import json
import pandas as pd
import numpy as np
import csv

api_key = "af2e09fb77412ef59a63d898762b07c752aa134c47563928cc4251f2896f3842"

# upload file .zip
url = "https://www.virustotal.com/api/v3/files"

files = { "file": (r"C:\Users\Home88\PycharmProjects\Python_task14\protected_archive.zip", open(r"C:\Users\Home88\PycharmProjects\Python_task14\protected_archive.zip", "rb"), "application/x-zip-compressed") }
payload = { "password": "netology" }
headers = {
    "accept": "application/json",
    "x-apikey": f"{api_key}"
}

response = requests.post(url, data=payload, files=files, headers=headers)
#print(response.text)

#получим ссылку на файл-анализ
url_link = response.json().get("data", {}).get("links", {}).get("self")
#print(url_link)


# API - get a file report
url = url_link

headers = {
    "accept": "application/json",
    "x-apikey": f"{api_key}"
}

response = requests.get(url, headers=headers)
#print(response.text)

# проанализируем полученный ответ и выведем список антивирусов обнаруживших вирус

obj = response.json()
list_antivirus_detected = []
for i in obj["data"]["attributes"]["results"].values():
    if i["category"] == "malicious":
        list_antivirus_detected.append(i["engine_name"])
print("Detected(всего антивирусов:", len(list_antivirus_detected),"):", ", ".join(list_antivirus_detected))

# выведем список результата работы антивирусов Fortinet, McAfee, Yandex, Sophos

list_antivirus = ["Fortinet", "McAfee", "Yandex", "Sophos"]
result_check = []
print("Результат проверки по заданным антивирусам:")
for i, j in obj["data"]["attributes"]["results"].items():
    if i in list_antivirus:
        result_check.append(j["category"])
        print(i, ":", j["category"])


# получим file_id в виде sha256
url_file_id = response.json().get("data", {}).get("links", {}).get("item")
url_file_id= str(urlsplit(url_file_id).path)# возьмет от url Только часть path
list_url_file_id= []
for id_path in url_file_id.rpartition("/"):
    list_url_file_id.append(id_path)
file_id = list_url_file_id[2]

# собираем url c file_id
scheme = "https"
netloc = "www.virustotal.com"
path = f"/api/v3/files/{file_id}/behaviour_summary"
query = ""
fragment = ""

url_file_id = urlunsplit((scheme, netloc, path, query, fragment))

#запрос get для получения summary file

url = url_file_id

headers = {
    "accept": "application/json",
    "x-apikey": f"{api_key}"
}

response = requests.get(url, headers=headers)

#print(response.text)

# parce file behavior and print
obj_sbox = response.json()
# выведем список удаленных файлов
list_dropped_files = dict(obj_sbox["data"]["files_dropped"][0])
print("File dropped:")
for i in list_dropped_files.values():
    print(list_dropped_files["path"])
# Выведем список доменов и IP-адресов
list_domain = (obj_sbox["data"]["memory_pattern_domains"])
print("List of domains:", list_domain)
# Выведем modules_loaded
list_module = (obj_sbox["data"]["modules_loaded"])
print("Modules_loaded:", list_module[:5])
# Выведем files_opened
list_files_opened = (obj_sbox["data"]["files_opened"])
print("File_opened:", list_files_opened[:5])
