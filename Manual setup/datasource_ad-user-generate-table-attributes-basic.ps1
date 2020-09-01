try {
    $userPrincipalName = $formInput.selectedUser.UserPrincipalName
    HID-Write-Status -Message "Searching AD user [$userPrincipalName]" -Event Information
     
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } -Properties * | Select-Object displayname, samaccountname, userPrincipalName, mail, employeeID, Enabled
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