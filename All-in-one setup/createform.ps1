#HelloID variables
$PortalBaseUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users", "HID_administrators")
 
# Create authorization headers with HelloID API key
$pair = "$apiKey" + ":" + "$apiSecret"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$key = "Basic $base64"
$headers = @{"authorization" = $Key}
# Define specific endpoint URI
if($PortalBaseUrl.EndsWith("/") -eq $false){
    $PortalBaseUrl = $PortalBaseUrl + "/"
}
 
function Write-ColorOutput($ForegroundColor) {
  $fc = $host.UI.RawUI.ForegroundColor
  $host.UI.RawUI.ForegroundColor = $ForegroundColor
  
  if ($args) {
      Write-Output $args
  }
  else {
      $input | Write-Output
  }

  $host.UI.RawUI.ForegroundColor = $fc
}
 
$variableName = "ADusersSearchOU"
$variableGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automation/variables/named/$variableName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.automationVariableGuid)) {
        #Create Variable
        $body = @{
            name = "$variableName";
            value = '[{ "OU": "OU=Employees,OU=Users,OU=Enyoi,DC=enyoi-media,DC=local"},{ "OU": "OU=Disabled,OU=Users,OU=Enyoi,DC=enyoi-media,DC=local"},{"OU": "OU=External,OU=Users,OU=Enyoi,DC=enyoi-media,DC=local"}]';
            secret = "false";
            ItemType = 0;
        }
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automation/variable")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $variableGuid = $response.automationVariableGuid

        Write-ColorOutput Green "Variable '$variableName' created: $variableGuid"
    } else {
        $variableGuid = $response.automationVariableGuid
        Write-ColorOutput Yellow "Variable '$variableName' already exists: $variableGuid"
    }
} catch {
    Write-ColorOutput Red "Variable '$variableName'"
    $_
}
  
  
  
$taskName = "AD-user-generate-table-wildcard"
$taskGetUsersGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automationtasks?search=$taskName&container=1")
    $response = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false) | Where-Object -filter {$_.name -eq $taskName}
  
    if([string]::IsNullOrEmpty($response.automationTaskGuid)) {
        #Create Task
  
        $body = @{
            name = "$taskName";
            useTemplate = "false";
            powerShellScript = @'
try {
    $searchValue = $formInput.searchUser
    $searchQuery = "*$searchValue*"
      
      
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        Hid-Add-TaskResult -ResultValue []
    }else{
        Hid-Write-Status -Message "SearchQuery: $searchQuery" -Event Information
        Hid-Write-Status -Message "SearchBase: $searchOUs" -Event Information
        HID-Write-Summary -Message "Searching for: $searchQuery" -Event Information
          
        $ous = $searchOUs | ConvertFrom-Json
        $users = foreach($item in $ous) {
            Get-ADUser -Filter {Name -like $searchQuery -or DisplayName -like $searchQuery -or userPrincipalName -like $searchQuery -or email -like $searchQuery} -SearchBase $item.ou -properties *
        }
          
        $users = $users | Sort-Object -Property DisplayName
        $resultCount = @($users).Count
        Hid-Write-Status -Message "Result count: $resultCount" -Event Information
        HID-Write-Summary -Message "Result count: $resultCount" -Event Information
          
        if($resultCount -gt 0){
            foreach($user in $users){
                $returnObject = @{SamAccountName=$user.SamAccountName; displayName=$user.displayName; UserPrincipalName=$user.UserPrincipalName; Description=$user.Description; Department=$user.Department; Title=$user.Title; Company=$user.company}
                Hid-Add-TaskResult -ResultValue $returnObject
            }
        } else {
            Hid-Add-TaskResult -ResultValue []
        }
    }
} catch {
    HID-Write-Status -Message "Error searching AD user [$searchValue]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Error searching AD user [$searchValue]" -Event Failed
      
    Hid-Add-TaskResult -ResultValue []
}
  
'@;
            automationContainer = "1";
            variables = @(@{name = "searchOUs"; value = "{{variable.ADusersSearchOU}}"; typeConstraint = "string"; secret = "False"})
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskGetUsersGuid = $response.automationTaskGuid

        Write-ColorOutput Green "Powershell task '$taskName' created: $taskGetUsersGuid"    
    } else {
        #Get TaskGUID
        $taskGetUsersGuid = $response.automationTaskGuid
        Write-ColorOutput Yellow "Powershell task '$taskName' already exists: $taskGetUsersGuid"
    }
} catch {
    Write-ColorOutput Red "Powershell task '$taskName'"
    $_
}
  
  
  
$dataSourceName = "AD-user-generate-table-wildcard"
$dataSourceGetUsersGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/datasource/named/$dataSourceName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
        #Create DataSource
        $body = @{
            name = "$dataSourceName";
            type = "3";
            model = @(@{key = "Company"; type = 0}, @{key = "Department"; type = 0}, @{key = "Description"; type = 0}, @{key = "displayName"; type = 0}, @{key = "SamAccountName"; type = 0}, @{key = "Title"; type = 0}, @{key = "UserPrincipalName"; type = 0});
            automationTaskGUID = "$taskGetUsersGuid";
            input = @(@{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "searchUser"; type = "0"; options = "1"})
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/datasource")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
          
        $dataSourceGetUsersGuid = $response.dataSourceGUID
        Write-ColorOutput Green "Task data source '$dataSourceName' created: $dataSourceGetUsersGuid"
    } else {
        #Get DatasourceGUID
        $dataSourceGetUsersGuid = $response.dataSourceGUID
        Write-ColorOutput Yellow "Task data source '$dataSourceName' already exists: $dataSourceGetUsersGuid"
    }
} catch {
    Write-ColorOutput Red "Task data source '$dataSourceName'"
    $_
}  
  
  
$taskName = "AD-user-generate-table-attributes-basic"
$taskGetUserDetailsGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automationtasks?search=$taskName&container=1")
    $response = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false) | Where-Object -filter {$_.name -eq $taskName}
  
    if([string]::IsNullOrEmpty($response.automationTaskGuid)) {
        #Create Task
  
        $body = @{
            name = "$taskName";
            useTemplate = "false";
            powerShellScript = @'
try {
    $userPrincipalName = $formInput.selectedUser.UserPrincipalName
    HID-Write-Status -Message "Searching AD user [$userPrincipalName]" -Event Information
      
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } -Properties * | select displayname, samaccountname, userPrincipalName, mail, employeeID, Enabled
    HID-Write-Status -Message "Finished searching AD user [$userPrincipalName]" -Event Information
      
    foreach($tmp in $adUser.psObject.properties)
    {
        $returnObject = @{name=$tmp.Name; value=$tmp.value}
        Hid-Add-TaskResult -ResultValue $returnObject
    }
      
    HID-Write-Status -Message "Finished retrieving AD user [$userPrincipalName] basic attributes" -Event Success
    HID-Write-Summary -Message "Finished retrieving AD user [$userPrincipalName] basic attributes" -Event Success
} catch {
    HID-Write-Status -Message "Error retrieving AD user [$userPrincipalName] basic attributes. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Error retrieving AD user [$userPrincipalName] basic attributes" -Event Failed
      
    Hid-Add-TaskResult -ResultValue []
}
'@;
            automationContainer = "1";
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskGetUserDetailsGuid = $response.automationTaskGuid

        Write-ColorOutput Green "Powershell task '$taskName' created: $taskGetUserDetailsGuid"    
    } else {
        #Get TaskGUID
        $taskGetUserDetailsGuid = $response.automationTaskGuid
        Write-ColorOutput Yellow "Powershell task '$taskName' already exists: $taskGetUserDetailsGuid"
    }
} catch {
    Write-ColorOutput Red "Powershell task '$taskName'"
    $_
}
  
  
  
$dataSourceName = "AD-user-generate-table-attributes-basic"
$dataSourceGetUserDetailsGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/datasource/named/$dataSourceName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
        #Create DataSource
        $body = @{
            name = "$dataSourceName";
            type = "3";
            model = @(@{key = "name"; type = 0}, @{key = "value"; type = 0});
            automationTaskGUID = "$taskGetUserDetailsGuid";
            input = @(@{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "selectedUser"; type = "0"; options = "1"})
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/datasource")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
          
        $dataSourceGetUserDetailsGuid = $response.dataSourceGUID
        Write-ColorOutput Green "Task data source '$dataSourceName' created: $dataSourceGetUserDetailsGuid"
    } else {
        #Get DatasourceGUID
        $dataSourceGetUserDetailsGuid = $response.dataSourceGUID
        Write-ColorOutput Yellow "Task data source '$dataSourceName' already exists: $dataSourceGetUserDetailsGuid"
    }
} catch {
    Write-ColorOutput Red "Task data source '$dataSourceName'"
    $_
}
 
 
$taskName = "AD-user-generate-table-groupmemberships"
$taskGetADUserGroupMembershipsGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/automationtasks?search=$taskName&container=1")
    $response = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false) | Where-Object -filter {$_.name -eq $taskName}
  
    if([string]::IsNullOrEmpty($response.automationTaskGuid)) {
        #Create Task
  
        $body = @{
            name = "$taskName";
            useTemplate = "false";
            powerShellScript = @'
try {
    $userPrincipalName = $formInput.selectedUser.UserPrincipalName
    HID-Write-Status -Message "Searching AD user [$userPrincipalName]" -Event Information
      
    if([String]::IsNullOrEmpty($userPrincipalName) -eq $true){
        Hid-Add-TaskResult -ResultValue []
    } else {
        $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
        HID-Write-Status -Message "Finished searching AD user [$userPrincipalName]" -Event Information
        HID-Write-Summary -Message "Found AD user [$userPrincipalName]" -Event Information
          
        $groups = Get-ADPrincipalGroupMembership $adUser | select name | Sort-Object name
        $groups = $groups | ? {$_.Name -ne "Domain Users"}
        $resultCount = @($groups).Count
          
        Hid-Write-Status -Message "Groupmemberships: $resultCount" -Event Information
        HID-Write-Summary -Message "Groupmemberships: $resultCount" -Event Information
          
        if($resultCount -gt 0) {
            foreach($group in $groups)
            {
                $returnObject = @{name="$($group.name)";}
                Hid-Add-TaskResult -ResultValue $returnObject
            }
        } else{
            Hid-Add-TaskResult -ResultValue []
        }
    }
} catch {
    HID-Write-Status -Message "Error getting groupmemberships [$userPrincipalName]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Error getting groupmemberships [$userPrincipalName]" -Event Failed
      
    Hid-Add-TaskResult -ResultValue []
}
'@;
            automationContainer = "1";
            variables = @()
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/automationtasks/powershell")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
        $taskGetADUserGroupMembershipsGuid = $response.automationTaskGuid

        Write-ColorOutput Green "Powershell task '$taskName' created: $taskGetADUserGroupMembershipsGuid"   
    } else {
        #Get TaskGUID
        $taskGetADUserGroupMembershipsGuid = $response.automationTaskGuid
        Write-ColorOutput Yellow "Powershell task '$taskName' already exists: $taskGetADUserGroupMembershipsGuid"
    }
} catch {
    Write-ColorOutput Red "Powershell task '$taskName'"
    $_
}
  
  
  
$dataSourceName = "AD-user-generate-table-groupmemberships"
$dataSourceGetADUserGroupMembershipsGuid = ""
  
try {
    $uri = ($PortalBaseUrl +"api/v1/datasource/named/$dataSourceName")
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
  
    if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
        #Create DataSource
        $body = @{
            name = "$dataSourceName";
            type = "3";
            model = @(@{key = "name"; type = 0});
            automationTaskGUID = "$taskGetADUserGroupMembershipsGuid";
            input = @(@{description = ""; translateDescription = "False"; inputFieldType = "1"; key = "selectedUser"; type = "0"; options = "1"})
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/datasource")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
          
        $dataSourceGetADUserGroupMembershipsGuid = $response.dataSourceGUID
        Write-ColorOutput Green "Task data source '$dataSourceName' created: $dataSourceGetADUserGroupMembershipsGuid"
    } else {
        #Get DatasourceGUID
        $dataSourceGetADUserGroupMembershipsGuid = $response.dataSourceGUID
        Write-ColorOutput Yellow "Task data source '$dataSourceName' already exists: $dataSourceGetADUserGroupMembershipsGuid"
    }
} catch {
    Write-ColorOutput Red "Task data source '$dataSourceName'"
    $_
}  
  
  
  
$formName = "AD Account - Show details"
$formGuid = ""
  
try
{
    try {
        $uri = ($PortalBaseUrl +"api/v1/forms/$formName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
    } catch {
        $response = $null
    }
  
    if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true))
    {
        #Create Dynamic form
        $form = @"
[
  {
    "label": "Select user account",
    "fields": [
      {
        "key": "searchfield",
        "templateOptions": {
          "label": "Search",
          "placeholder": "Username or email address"
        },
        "type": "input",
        "summaryVisibility": "Hide element",
        "requiresTemplateOptions": true
      },
      {
        "key": "grid",
        "templateOptions": {
          "label": "Select user account",
          "required": true,
          "grid": {
            "columns": [
              {
                "headerName": "DisplayName",
                "field": "displayName"
              },
              {
                "headerName": "UserPrincipalName",
                "field": "UserPrincipalName"
              },
              {
                "headerName": "Department",
                "field": "Department"
              },
              {
                "headerName": "Title",
                "field": "Title"
              },
              {
                "headerName": "Description",
                "field": "Description"
              }
            ],
            "height": 300,
            "rowSelection": "single"
          },
          "dataSourceConfig": {
            "dataSourceGuid": "$dataSourceGetUsersGuid",
            "input": {
              "propertyInputs": [
                {
                  "propertyName": "searchUser",
                  "otherFieldValue": {
                    "otherFieldKey": "searchfield"
                  }
                }
              ]
            }
          },
          "useFilter": false
        },
        "type": "grid",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      }
    ]
  },
  {
    "label": "Details",
    "fields": [
      {
        "key": "details",
        "templateOptions": {
          "label": "Basic attributes",
          "required": false,
          "grid": {
            "columns": [
              {
                "headerName": "Name",
                "field": "name"
              },
              {
                "headerName": "Value",
                "field": "value"
              }
            ],
            "height": 350,
            "rowSelection": "single"
          },
          "dataSourceConfig": {
            "dataSourceGuid": "$dataSourceGetUserDetailsGuid",
            "input": {
              "propertyInputs": [
                {
                  "propertyName": "selectedUser",
                  "otherFieldValue": {
                    "otherFieldKey": "grid"
                  }
                }
              ]
            }
          },
          "useFilter": false
        },
        "type": "grid",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      },
      {
        "key": "memberships",
        "templateOptions": {
          "label": "Memberships",
          "required": false,
          "grid": {
            "columns": [
              {
                "headerName": "Name",
                "field": "name"
              }
            ],
            "height": 300,
            "rowSelection": "single"
          },
          "dataSourceConfig": {
            "dataSourceGuid": "$dataSourceGetADUserGroupMembershipsGuid",
            "input": {
              "propertyInputs": [
                {
                  "propertyName": "selectedUser",
                  "otherFieldValue": {
                    "otherFieldKey": "grid"
                  }
                }
              ]
            }
          },
          "useFilter": false
        },
        "type": "grid",
        "summaryVisibility": "Show",
        "requiresTemplateOptions": true
      }
    ]
  }
]
"@
  
        $body = @{
            Name = "$formName";
            FormSchema = $form
        }
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/forms")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
  
        $formGuid = $response.dynamicFormGUID
        Write-ColorOutput Green "Dynamic form '$formName' created: $formGuid"
    } else {
        $formGuid = $response.dynamicFormGUID
        Write-ColorOutput Yellow "Dynamic form '$formName' already exists: $formGuid"
    }
} catch {
    Write-ColorOutput Red "Dynamic form '$formName'"
    $_
}
  
  
  
  
$delegatedFormAccessGroupGuids = @()

foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-ColorOutput Green "HelloID (access)group '$group' successfully found: $delegatedFormAccessGroupGuid"
    } catch {
        Write-ColorOutput Red "HelloID (access)group '$group'"
        $_
    }
}
  
  
  
$delegatedFormName = "AD Account - Show details"
$delegatedFormGuid = ""
$delegatedFormCreated = $false
  
try {
    try {
        $uri = ($PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false
    } catch {
        $response = $null
    }
  
    if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
        #Create DelegatedForm
        $body = @{
            name = "$delegatedFormName";
            dynamicFormGUID = "$formGuid";
            isEnabled = "True";
            accessGroups = $delegatedFormAccessGroupGuids;
            useFaIcon = "True";
            faIcon = "fa fa-search";
        }  
  
        $body = $body | ConvertTo-Json
  
        $uri = ($PortalBaseUrl +"api/v1/delegatedforms")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Verbose:$false -Body $body
  
        $delegatedFormGuid = $response.delegatedFormGUID
        Write-ColorOutput Green "Delegated form '$delegatedFormName' created: $delegatedFormGuid"
        $delegatedFormCreated = $true
    } else {
        #Get delegatedFormGUID
        $delegatedFormGuid = $response.delegatedFormGUID
        Write-ColorOutput Yellow "Delegated form '$delegatedFormName' already exists: $delegatedFormGuid"
    }
} catch {
    Write-ColorOutput Red "Delegated form '$delegatedFormName'"
    $_
}