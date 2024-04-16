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
    writer.writerow(['Group', 'Percentage'])

    # Iterate through all folders and their files in the test datasets directory
    for folder in os.listdir(baseDirectory):
        folderPath = os.path.join(baseDirectory, folder)
        totalFiles = 0
        correctPredictions = 0
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
                    # Run the cURL command and capture the JSON response
                    response = subprocess.run(curlCMD, stdout=subprocess.PIPE)
                    response = response.stdout.decode('utf-8')
                    # Extract the prediction from the JSON response
                    prediction = re.search(r'"malware":\s*(\d)', response)
                    if prediction:
                        prediction = int(prediction.group(1))
                        if prediction == 1:
                            correctPredictions += 1
                        totalFiles += 1 

            try:
                percentage = (correctPredictions / totalFiles) * 100
                writer.writerow([folder, "{:.2f}%".format(percentage)])
            except ZeroDivisionError:
                writer.writerow([folder, "0%"])


print("Finished processing test datasets.")
