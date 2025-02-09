# Microsoft Threat Intelligence Cleanup Tool

## Background

we faced a critical issue where an unexpected influx of thousands of Indicators of Compromise (IOCs) was injected by one of our threat intelligence providers. The sheer volume of these IOCs, combined with the lack of an efficient cleanup mechanism, created significant operational challenges.
Existing solutions for managing and removing these IOCs were either impractical or required waiting for the natural expiration of the indicators. 


## Motivation

To address this issue, I developed this script to automate the process of deleting unnecessary threat intelligence indicators from Microsoft Sentinel.

## Solution

This repository contains a Go script that utilizes the Microsoft Azure API to delete threat intelligence indicators based on specific criteria. The script is designed to:

* List all threat intelligence indicators based on specified confidence levels and sources.
* Delete each indicator using the Azure API.

## Features

* **Concurrent Deletion**: Concurrent deletion of indicators using goroutines for improved performance.
* **Dynamic Configuration**: Modify the sources and confidence levels through command-line arguments.
* **Signal Handling**: Graceful shutdown on receiving a Ctrl-C signal.
* **Reusable HTTP Client**: Reusable HTTP client for efficient API calls.
* **JSON Decoder**: JSON decoder for efficient response parsing.

## Usage

### Prerequisites

1. Ensure you have the Azure CLI installed and authenticated.
2. Ensure Go is installed on your system.

### Steps

1. **Clone Repository**: Clone the repository:
   ```sh
   git clone https://github.com/SunChero/az_sentinel_ti_cleaner.git
   cd az_sentinel_ti_cleaner
   ```


2. **Get Azure Token**: Retrieve the Azure access token:
   ```sh
   export AZURE_TOKEN=$(az account get-access-token --query 'accessToken' --output tsv)
   ```


3. **Run Script:**: Run the script with the required parameters:
   ```sh
        go run main.go --source="Mandiant" 
         --subscription="az_sentinel_subscription" \
        --resourceGroup="az_sentinel_resourceGroup" \
        --workspace="az_sentinel_workspace" \
        --minConfidence=0 \ 
        --maxConfidence=70 
       
        
   ```
### Command-Line Arguments

-  `--subscription`: Specify the Azure subscription id REQUIRED (default: none).
-  `--resourceGroup`: Specify the Azure sentinel resource group REQUIRED (default: none).
-  `--workspace`: Specify the Azure sentinel workspace REQUIRED (default: none).
-  `--source`: Specify the source of threat intelligence indicators (default: "Mandiant").
-  `--minConfidence`: Specify the minimum confidence level (default: 0).
-  `--maxConfidence`: Specify the maximum confidence level (default: 50).



### Example
To delete threat intelligence indicators from the "Mandiant" source with a confidence level between 0 and 70:

```sh
    go run main.go --source="Mandiant" \ 
    --subscription="az_sentinel_subscription" \
    --resourceGroup="az_sentinel_resourceGroup" \
    --workspace="az_sentinel_workspace" \
    --minConfidence=0 \
    --maxConfidence=70  
```


### Contributions
If you have suggestions or improvements, please feel free to:

-   Open Issue: Open an issue.
-   Submit Pull Request: Submit a pull request.


### License
This project is licensed under the MIT License. See LICENSE for details.
