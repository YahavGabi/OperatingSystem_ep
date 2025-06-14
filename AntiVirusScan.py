import requests
import os
import time

def upload_file(url,api_key,file_path):

    params_post = {'apikey': api_key}
    with open(file_path,'rb')as file:
        files = {'file': file}
        response = requests.post(url, data = params_post, files = files)
        if response.status_code == 200:
            if response.headers['Content-Type'] == 'application/json':
                response_json = response.json()
                resource = response_json['resource']
                return resource
            else:
                print("Error,the response isn't in json format")
        else:
             print("Error, the file didn't send seccessfully to virus total :(")     
              
def is_file_malicious(url,api_key,resource):
    positives = []
    params_get = {'apikey':api_key,'resource':resource}
    response = requests.get(url,params_get)
    if response.status_code == 200:
        if response.headers['Content-Type'] == 'application/json':
            if response.json()['response_code'] == 1: 
                report = response.json()
                for engine, result in report['scans'].items():
                    if result['detected'] == True:
                        positives.append(engine)
                if len(positives)>0:
                    return 1
                else:
                    return 0
            else:
                print("Error,the file is still checked by virus total or doesn't exist in virus total data set")
        else:
            print("Error,the response isn't in json format")
    else:
        print("Error, the file wasn't check by virus total :(")
    return -1

def scan_single_file(file_path, api_key):
    scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    report_url = 'https://www.virustotal.com/vtapi/v2/file/report'

    print(f"\nScanning file: {file_path}")
    resource = upload_file(scan_url, api_key, file_path)
    if resource:
        time.sleep(15)
        status = is_file_malicious(report_url, api_key, resource)
        if status == -1:
            print("❌ Error during scan")
        elif status == 0:
            print("✅ The file isn't malicious")
        else:
            print("⚠️ WARNING: The file is malicious!")
    else:
        print("⚠️ Failed to upload file.")

def scan_directory_recursively(directory_path, api_key):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            scan_single_file(full_path, api_key)

if __name__ == "__main__":
    API_KEY = "4368a2eb7db33b07cc73175d0787e1bca74406838db159749809d32d11984b06"

    choice = input("Enter 1 to scan a single file, or 2 to scan a folder recursively: ")
    if choice == "1":
        file_path = input("Enter full path to the file: ")
        scan_single_file(file_path, API_KEY)
    elif choice == "2":
        folder_path = input("Enter full path to the folder: ")
        scan_directory_recursively(folder_path, API_KEY)
    else:
        print("Invalid choice. Please enter 1 or 2.")

