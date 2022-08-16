// Copyright (c) 2022 Snowflake Computing Inc. All rights reserved.

package gosnowflake

import (
    "strings"

    "github.com/danieljoos/wincred"
)

const (
    driverName = "SNOWFLAKE-GO-DRIVER"
    colonCharacterLength = 1
)

 func setCredential(host, user, credType, token string) {
    if token != "" {
        target := convertTarget(host, user, credType)
        cred := wincred.NewGenericCredential(target)
        logger.Debugf("token: %v", token)
        cred.CredentialBlob = []byte(token)
        cred.Persist = wincred.PersistLocalMachine
        cred.Write()
        logger.Debug("Wrote to Windows Credential Manager successfully")
    }
 }

func getCredential(host, user, credType string) string {
    target := convertTarget(host, user, credType)
    cred, err := wincred.GetGenericCredential(target)
    if err != nil {
        logger.Debugf("Failed to read target or could not find it in Windows Credential Manager. Error: %v", err)
        return ""
    }
    logger.Debug("Successfully read token. Returning as string")
    return string(cred.CredentialBlob)
}

 func deleteCredential(host, user, credType string) {
    target := convertTarget(host, user, credType)
    cred, _ := wincred.GetGenericCredential(target)
    if cred != nil {
        logger.Debug("HERE")
        if err := cred.Delete(); err == nil {
            logger.Debug("Deleted target in Windows Credential Manager successfully")
        }
    }
 }

  func convertTarget(host, user, credType string) string {
    host = strings.ToUpper(host)
    user = strings.ToUpper(user)
    credType = strings.ToUpper(credType)

    target := host + ":" + user + ":" + driverName + ":" + credType
    logger.Debugf("target: %v", target)
    return target
  }
