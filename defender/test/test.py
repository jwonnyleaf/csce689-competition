import os
import subprocess
import csv
import re

print("Processing test datasets...")

# Set path so you can run the script from any directory
baseDirectory = os.path.join(os.path.dirname(os.path.realpath(__file__)), "datasets")

# Create or open the CSV file to record the results
with open(baseDirectory + '/results.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Group', 'File Name', 'Malware', 'Truth', 'Response Time'])

    # Iterate through all folders and their files in the test datasets directory
    for folder in os.listdir(baseDirectory):
        folderPath = os.path.join(baseDirectory, folder)
        if os.path.isdir(folderPath):
            for file in os.listdir(folderPath):
                filePath = os.path.join(folderPath, file)
                if os.path.isfile(filePath):
                    curlCMD = [
                        'curl',
                        '-XPOST',
                        '--data-binary', f'@{filePath}',
                        'http://127.0.0.1:8080/',
                        '-H', 'Content-Type: application/octet-stream'
                    ]
                    # Run the cURL command and capture the output
                    result = subprocess.run(curlCMD, stdout=subprocess.PIPE)
                    if result.stdout:
                        resultStr = result.stdout.decode('utf-8')
                        # Extract the malware prediction and response time from the output
                        malware = re.search(r'Malware: (True|False)', resultStr).group(1)
                        truth = 'True' if 'mw' in folder else 'False'
                        responseTime = re.search(r'in (\d+\.\d+) seconds', resultStr).group(1)
                        writer.writerow([folder, file, malware, truth, responseTime])
                    if result.stderr:
                        print(f"Error processing {file}: {result.stderr}")

print("Finished processing test datasets.")
