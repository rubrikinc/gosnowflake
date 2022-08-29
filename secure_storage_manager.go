// Copyright (c) 2022 Snowflake Computing Inc. All rights reserved.

package gosnowflake

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/danieljoos/wincred"
)

const (
	driverName        = "SNOWFLAKE-GO-DRIVER"
	credCacheDirEnv   = "SF_TEMPORARY_CREDENTIAL_CACHE_DIR"
	credCacheFileName = "temporary_credential.json"
)

var (
	credCacheDir = ""
	credCache    = ""
)

func createCredentialCacheDir() {
	credCacheDir = os.Getenv(credCacheDirEnv)
	if credCacheDir == "" {
		switch runtime.GOOS {
		case "windows":
			credCacheDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Snowflake", "Caches")
		case "darwin":
			home := os.Getenv("HOME")
			if home == "" {
				logger.Info("HOME is blank.")
			}
			credCacheDir = filepath.Join(home, "Library", "Caches", "Snowflake")
		default:
			home := os.Getenv("HOME")
			if home == "" {
				logger.Info("HOME is blank")
			}
			credCacheDir = filepath.Join(home, ".cache", "snowflake")
		}
	}

	if _, err := os.Stat(credCacheDir); os.IsNotExist(err) {
		if err = os.MkdirAll(credCacheDir, os.ModePerm); err != nil {
			logger.Debugf("failed to create cache directory. %v, err: %v. ignored\n", credCacheDir, err)
		}
	}
	credCache = filepath.Join(credCacheDir, credCacheFileName)
	logger.Infof("cache directory: %v", cacheFileName)
}

func setCredential(host, user, credType, token string) {
	if token == "" {
		logger.Debug("no token provided")
	} else {
		if runtime.GOOS == "windows" {
			target := convertTarget(host, user, credType)
			cred := wincred.NewGenericCredential(target)
			cred.CredentialBlob = []byte(token)
			cred.Persist = wincred.PersistLocalMachine
			cred.Write()
			logger.Debug("Wrote to Windows Credential Manager successfully")
		} else if runtime.GOOS == "linux" {
			createCredentialCacheDir()
			writeTemporaryCredential(host, user, credType, token)
		} else {
			logger.Debug("OS not supported for Local Secure Storage")
		}
	}
}

func getCredential(host, user, credType string) string {
	target := convertTarget(host, user, credType)
	cred := ""
	if runtime.GOOS == "windows" {
		winCred, err := wincred.GetGenericCredential(target)
		if err != nil {
			logger.Debugf("Failed to read target or could not find it in Windows Credential Manager. Error: %v", err)
			return ""
		}
		logger.Debug("Successfully read token. Returning as string")
		cred = string(winCred.CredentialBlob)
	} else if runtime.GOOS == "linux" {
		createCredentialCacheDir()
		cred = readTemporaryCredential(host, user, credType)
	} else {
		logger.Debug("OS not supported for Local Secure Storage")
	}
	return cred
}

func deleteCredential(host, user, credType string) {
	target := convertTarget(host, user, credType)
	if runtime.GOOS == "windows" {
		cred, _ := wincred.GetGenericCredential(target)
		if cred != nil {
			if err := cred.Delete(); err == nil {
				logger.Debug("Deleted target in Windows Credential Manager successfully")
			}
		}
	} else if runtime.GOOS == "linux" {
		deleteTemporaryCredential(host, user, credType)
	}
}

// Reads temporary credential file when OS is Linux.
func readTemporaryCredential(host, user, credType string) string {
	if credCacheDir == "" {
		logger.Debug("Cache file doesn't exist")
		return ""
	}
	jsonData, err := ioutil.ReadFile(credCache)
	if err != nil {
		logger.Debugf("error: %v", err)
	}
	var tempCred map[string]string
	target := convertTarget(host, user, credType)
	err = json.Unmarshal([]byte(jsonData), &tempCred)
	cred := tempCred[target]
	logger.Debug("Successfully read token. Returning as string")
	return cred
}

// Writes to temporary credential file when OS is Linux.
func writeTemporaryCredential(host, user, credType, token string) {
	if token == "" {
		logger.Debug("No token provided")
	} else {
		if credCacheDir == "" {
			logger.Debug("Cache file doesn't exist")
		} else {
			target := convertTarget(host, user, credType)
			buf := make(map[string]string)
			buf[target] = token

			j, err := json.Marshal(buf)
			if err != nil {
				logger.Debugf("failed to convert credential to JSON.")
			}
			if err = ioutil.WriteFile(credCache, j, 0644); err != nil {
				logger.Debugf("Failed to write the cache file. File: %v err: %v.", credCache, err)
			}
		}
	}
}

func deleteTemporaryCredential(host, user, credType string) {
	if credCacheDir == "" {
		logger.Debug("Cache file doesn't exist")
	} else {
		logger.Debug("")
	}
}

func convertTarget(host, user, credType string) string {
	host = strings.ToUpper(host)
	user = strings.ToUpper(user)
	credType = strings.ToUpper(credType)
	target := host + ":" + user + ":" + driverName + ":" + credType
	return target
}
