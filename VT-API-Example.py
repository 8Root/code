import os
import time
import requests
import hashlib

# VirusTotal API v3 key
VT_API_KEY = ''

# Path to the folder to monitor
DOWNLOAD_FOLDER = ''

# Function to calculate the SHA256 hash of a file
def calculate_hash(file_path):
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256()
        while chunk := f.read(8192):
            file_hash.update(chunk)
        return file_hash.hexdigest()

# Function to check the VirusTotal API for a given file hash
def check_virustotal(file_hash):
    headers = {
        'x-apikey': VT_API_KEY
    }
    params = {
        'include': 'clean'
    }
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()['data']
        attributes = data['attributes']
        last_analysis_stats = attributes['last_analysis_stats']
        if last_analysis_stats['malicious'] == 0:
            return True
    return False

# Start monitoring the download folder
while True:
    for filename in os.listdir(DOWNLOAD_FOLDER):
        file_path = os.path.join(DOWNLOAD_FOLDER, filename)
        if os.path.isfile(file_path):
            file_hash = calculate_hash(file_path)
            if check_virustotal(file_hash):
                print(f'File {filename} is secure')
            else:
                print(f'File {filename} is not secure')
    time.sleep(1)
