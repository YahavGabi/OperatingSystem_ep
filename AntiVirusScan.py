import requests
import time
import os

SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

def upload_file(url, api_key, file_path):
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            params_post = {'apikey': api_key}
            response = requests.post(url, data=params_post, files=files)
            if response.status_code == 200:
                if response.headers.get('Content-Type') == 'application/json':
                    response_json = response.json()
                    return response_json.get('resource')
    except Exception as e:
        print(f"Error uploading file {file_path}: {e}")
    return None

def is_file_malicious(url, api_key, resource):
    try:
        params_get = {'apikey': api_key, 'resource': resource}
        response = requests.get(url, params=params_get)
        if response.status_code == 200:
            if response.headers.get('Content-Type') == 'application/json':
                json_resp = response.json()
                if json_resp.get('response_code') == 1:
                    positives = [engine for engine, res in json_resp.get('scans', {}).items() if res.get('detected')]
                    return 1 if len(positives) > 0 else 0
    except Exception as e:
        print(f"Error checking file maliciousness: {e}")
    return -1

def scan_single_file(file_path, api_key):
    resource = upload_file(SCAN_URL, api_key, file_path)
    if resource:
        time.sleep(15)  
        return is_file_malicious(REPORT_URL, api_key, resource)
    else:
        return -1

def scan_directory_recursively(directory_path, api_key):
    results = []
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            result = scan_single_file(full_path, api_key)
            results.append((full_path, result))
    return results

