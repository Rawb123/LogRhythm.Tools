using namespace System

Function Get-Guid {
    <#
    .SYNOPSIS
        Determine if a user entered a valid guid.
    .PARAMETER Value
        String to evaluate as a guid.
    .EXAMPLE
        PS C:\> Get-InputGuid -Value 3da80399-a3a9-4e2f-91fc-809064cc33c7 -OldValue cbb3790d-b8c4-4102-8cbd-81b284639511

        Value                                Valid Changed
        -----                                ----- -------
        cbb3790d-b8c4-4102-8cbd-81b284639511  True    True
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value
    )


    # Return object 
    $Return = [PSCustomObject]@{
        Value = $null
        Valid = $false
    }

    # Test new TenantId/guid entered by user
    $ValidGuid = [guid]::Empty
    if ([guid]::TryParse($Value, [ref]$ValidGuid)) {

        # All tests passed, return new Url + TenantId combination
        $Return.Valid = $true
        $Return.Value = $Value
    }

    return $Return
}