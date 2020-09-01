try {
    $userPrincipalName = $formInput.selectedUser.UserPrincipalName
    HID-Write-Status -Message "Searching AD user [$userPrincipalName]" -Event Information
     
    if([String]::IsNullOrEmpty($userPrincipalName) -eq $true){
        Hid-Add-TaskResult -ResultValue []
    } else {
        $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
        HID-Write-Status -Message "Finished searching AD user [$userPrincipalName]" -Event Information
        HID-Write-Summary -Message "Found AD user [$userPrincipalName]" -Event Information
         
        $groups = Get-ADPrincipalGroupMembership $adUser | Select-Object name | Sort-Object name
        $groups = $groups | Where-Object {$_.Name -ne "Domain Users"}
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