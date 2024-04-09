import os
import json
import shutil

def count_missing_witness(json_data, filename):
    missing_files = set()
    counter = 0

    tx_type = "l"
    for vin_item in json_data["vin"]:
        if "witness" in vin_item:
            tx_type = "s"
            break

    for vin_item in json_data["vin"]:
        if vin_item["prevout"]["scriptpubkey_type"] == "p2sh":
            if "witness" not in vin_item and tx_type=="s":
                counter += 1
                missing_files.add(filename)
    return counter, missing_files 

def main():
    directory = './mempool'
    counter = 0
    missing_files = set()

    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            with open(os.path.join(directory, filename)) as f:
                data = json.load(f)
                count, files = count_missing_witness(data, filename)
                counter += count
                missing_files.update(files)
    
    print("Total missing witnesses:", counter)
    print("Unique files with missing witnesses:", len(missing_files))
    for file in missing_files:
        print(file)
    
    if missing_files:
        if not os.path.exists('./data'):
            os.makedirs('./data')
        
        for file in missing_files:
            shutil.copy2(os.path.join(directory, file), './data')
            print(f"File '{file}' copied to './data' directory.")

if __name__ == "__main__":
    main()   
