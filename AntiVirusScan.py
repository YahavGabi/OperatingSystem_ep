import requests
import os

def upload_file(url,api_kei,file_path):

    params_post = {'apikey': api_kei}
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
def is_file_malicious(url,api_kei,resource):
    positives = []
    params_get = {'apikey':api_kei,'resource':resource}
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

if __name__ == "__main__":
    
    API_KEY = "4368a2eb7db33b07cc73175d0787e1bca74406838db159749809d32d11984b06"
    file_path = "path/to/your/file/.py"
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    
    resource = upload_file(url, API_KEY, file_path)
    report_url = "https://www.virustotal.com/vtapi/v2/file/report"
    status = is_file_malicious(report_url,API_KEY,resource)

    if status == -1:
        print("Error")
    elif status == 0:
        print("The file isn't malicious")
    else:
        print("WARNING: the file is malicious")

   

