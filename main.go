package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	apiVersion = "2024-03-01"
)

var (
	graphTI = map[string]interface{}{
		"pageSize":      10,
		"minConfidence": 0,
		"maxConfidence": 50,
		"sources": []string{
			"Mandiant",
		},
		"sortBy": []map[string]string{
			{
				"itemKey":   "lastUpdatedTimeUtc",
				"sortOrder": "descending",
			},
		},
	}
	token         string
	minConfidence int
	maxConfidence int
	sources       string
	subscription  string
	workspace     string
	resourceGroup string
)

func main() {
	// Get the token by executing az account get-access-token
	token = getAzureToken()
	if token == "" {
		log.Fatal("Azure authentication token is required")
	}
	var count = 0
	// Parse command-line arguments
	flag.StringVar(&sources, "source", "Mandiant", "Source of threat intelligence ")
	flag.StringVar(&subscription, "subscription", "none", "Azure subscription id REQUIRED ")
	flag.StringVar(&resourceGroup, "resourceGroup", "none", "Azure resource group REQUIRED ")
	flag.StringVar(&workspace, "workspace", "", "Azure Sentinel workspace name REQUIRED ")
	flag.IntVar(&minConfidence, "minConfidence", 0, "Minimum confidence for threat intelligence (Default 0)")
	flag.IntVar(&maxConfidence, "maxConfidence", 50, "Maximum confidence for threat intelligence")
	flag.Parse()
	if subscription == "" || resourceGroup == "" || workspace == "" {
		fmt.Println("Error: --subscription, --resourceGroup, and --workspace are required")
		flag.Usage()
		os.Exit(1)
	}
	// Update graphTI map with the provided values
	graphTI["sources"] = strings.Split(sources, ",")
	graphTI["minConfidence"] = minConfidence
	graphTI["maxConfidence"] = maxConfidence

	// Set up signal handling to catch Ctrl-C
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Main loop
	doneChan := make(chan struct{})
	go func() {
		<-signalChan
		close(doneChan)
		fmt.Println("\nReceived an interrupt, stopping...")
	}()

	for {
		select {
		case <-doneChan:
			return
		default:
			deletedCount, err := processIndicators(doneChan)
			if err != nil {
				log.Fatalf("Failed to process indicators: %v", err)
			}
			if deletedCount == 0 {
				fmt.Println("No more indicators to delete.")
				return
			}
			count += deletedCount
			fmt.Printf("Deleted %d indicators.\n", count)
			time.Sleep(1 * time.Second) // Add sleep to prevent potential rate limiting
		}
	}
}

func getAzureToken() string {
	cmd := exec.Command("az", "account", "get-access-token", "--query", "accessToken", "--output", "tsv")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to get Azure access token: %v", err)
	}
	return strings.TrimSpace(string(output))
}

func processIndicators(doneChan <-chan struct{}) (int, error) {
	indicators, err := listThreatIndicators()
	if err != nil {
		return 0, fmt.Errorf("failed to list threat indicators: %v", err)
	}

	if len(indicators) == 0 {
		return 0, nil
	}

	var wg sync.WaitGroup
	errors := make(chan error, len(indicators))
	deletedCount := len(indicators)

	for _, id := range indicators {
		wg.Add(1)
		go func(indicatorID string) {
			defer wg.Done()
			select {
			case <-doneChan:
				return
			default:
				err := deleteThreatIndicator(indicatorID)
				if err != nil {
					errors <- fmt.Errorf("failed to delete indicator with ID %s: %v", indicatorID, err)
				}
			}
		}(id)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		fmt.Println(err)
	}

	return deletedCount, nil
}

func listThreatIndicators() ([]string, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s/providers/Microsoft.SecurityInsights/threatintelligence/main/queryIndicators?api-version=%s", subscription, resourceGroup, workspace, apiVersion)

	body, err := json.Marshal(graphTI)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal graphTI: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %v", resp.StatusCode)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var result struct {
		Value []struct {
			ID string `json:"name"`
		} `json:"value"`
	}

	err = json.Unmarshal(respBody, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	var ids []string
	for _, item := range result.Value {
		ids = append(ids, item.ID)
	}

	return ids, nil
}

func deleteThreatIndicator(fullid string) error {
	id := fullid
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s/providers/Microsoft.SecurityInsights/threatintelligence/main/indicators/%s?api-version=%s", subscription, resourceGroup, workspace, id, apiVersion)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %v", resp.StatusCode)
	}
	fmt.Println(fullid)
	return nil
}

// func extractRealID(fullID string) string {
// 	parts := strings.Split(fullID, "/")
// 	return parts[len(parts)-1]
// }
