function Calculate-Severity {
    param(
        [PSCustomObject]$Alert
    )

    switch ($Alert.RuleName) {
        "Detect-AuditLogCleared"          { return "Critical" }
        "Detect-AccessibilityFeatureAbuse" { return "Critical" }
        "Detect-ProcessHollowing"          { return "Critical" }
        
        "Detect-SecurityGroupModified"     { return "High" }
        "Detect-NewServiceInstallation"    { return "High" }
        "Detect-SecurityToolTermination"   { return "High" }
        "Detect-LsassHandleRequest"        { return "High" }
        "Detect-TaskPersistence"           { return "High" }
        "Detect-RogueAccountCreation"      { return "High" }
        
        "Detect-AnomalousLogonType"       { return "Medium" }
        "Detect-ExplicitCredentialsUse"    { return "Medium" }
        "Detect-LivingOffTheLandBinaries"  { return "Medium" }
        "Detect-EncodedPowerShell"         { return "Medium" }
        "Detect-SuspiciousFlags"           { return "Medium" }
        "Detect-TempExecution"             { return "Medium" }
        "Detect-OfficeSpawn"               { return "Medium" }
        
        "Detect-AccountLockoutLoop"        { return "Low" }
        "Detect-PasswordPolicyTampering"   { return "Low" }
        "Detect-PasswordReset"             { return "Low" }
        
        default                            { return "Low" }
    }
}