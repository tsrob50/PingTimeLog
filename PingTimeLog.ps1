<#
.SYNOPSIS
Run ping against an array of computers, log response time in Log Analytics for trending.
.DESCRIPTION
This is a simple network monitoring script.  There are many other like it available on the interwebs that are probably more robust but this is free and fits my needs.  
You can modify it as you see fit.

This tool is limited in it's intent,  I wanted to trend round trip ICMP Ping time over my WAN circuits for trending and to alert on a failure.
The tool sends a ping to a list (array) of servers or IP's and records the response time to Azure Log Analytics.  From there, you can monitor for 
response failures or trend out response times.  I have to thank Adam Conkle for the basis of gathering and sorting the ping data.  More information here:
https://gallery.technet.microsoft.com/scriptcenter/Ping-Test-Detect-network-bd7ee873

Once the script gathers the ping information it writes it to Azure Log Analytics.  The function provided below is straight out of a series I did on Log Analytics.  
More information can be found here http://www.ciraltos.com/azure-oms-log-analytics-step-by-step-data-collector-api/
The function requires a date/time, Log Analytics Type (this is analogous to a table in SQL) and a hashtable.  It will then write that data to a given Log Analytics
Workspace.  IT MAY TAKE UP TO 30 MINUTES FOR DATA TO SHOW UP WHEN FIRST RAN. (sorry for yelling)

Running this directly from Azure Automation will not work.  It requires the Windows Ping command that is not available in Azure Automation.  A better option would be to run it from a hybrid 
working at your main data center to track response time to your remote sites.  Or, it could be ran from a server as a scheduled task.

The $customerID variable will need to be updated with your Log Analytics Workspace ID as well as the $sharedKey variable with the workspace Key.

Change the $waitSec variable to change how frequently the ping command runs.  Default is 60 seconds.

Use this query to chart the response times in your OMS Workspace:

//Log Analytics timechart query
//Change the first line to the name of the Log Analytics type
PingTime_CL
| sort by TimeGenerated
| summarize TimeMS=avg(Duration_d) by bin(TimeGenerated, 1m), Address_s
| render timechart

* Note, the Hashtable values under Execution of Address, Duration, Error, PingResponse will be created as custom fields in Log Analytics as Address_s (string), Duration_d (double)
  Error_s, PingResponse_s.  Also, DateTime will have the custom field of DateTime_t (time).  Change any of these before running as needed.  For example, change Address to DestHost
  or DestGateWay to better describe what the script is pinging against.
.PARAMETER hoursToRun
How long the script will continue to run.  Could be 24 hours and started once a day at the same time, or an hour and started every hour.  Remember, if running with Azure Automaiton
Runbooks stop processing after about 3 hours.
.PARAMETER computers
An array of DNS resolvable names or IP addresses to ping
.INPUTS
Hours for the application to run.  Can be up to 24 when set as a scheduled task.  For example, set to run for 24 hours and run daily at midnight.  Azure Automation will not run
for over 3 hours.  For Azure Automation, set to a shorter time and start more frequently.  For example, run every hour for an hour.
List of computers to ping.  
.OUTPUTS
This script will output the ping responses to Log Analytics
.NOTES
Version:        1.1
Author:         Travis Roberts
Creation Date:  8/10/2018
Purpose/Change: Public Version.
.EXAMPLE
TBD
#>

############################################# Parameters ###################################################################

[cmdletbinding()]
Param(
    [Parameter(Mandatory = $false, Position = 0)]
    [Int32]$hoursToRun = (1),
    [parameter(Mandatory = $false, Position = 1)]
    [System.Array]$computers = ('server1.domain.com','10.10.10.1','www.google.com')
)

############################################# declarations ##################################################################

$ScriptStartTime = Get-Date 
$FirstRun = $true 

# Wait time between Ping tests
$waitSec = 60

# OMS Workspace information

# type is the workspace type or "table" the Write-OMSFunction will log data to
$type = "PingTime"

# Workspace ID for the Log Analytics workspace
$CustomerID = 'Put the Workspace ID here'

# A shared key needs to be set for OMS Workspace environment
# Below uses an encrypted variable from Azure Automation
# Uncomment the next two lines if using Azure Automation encrypted variable and comment the last line
# $automationVarName = 'VarNameHere'
# $sharedKey = Get-AutomationVariable -name $automationVarName
# Key Vault is another secure option for storing the value
# Less secure option is to put the key in the code
$SharedKey = 'Worksapce Key Here'



function Write-OMSLogfile {
<#
.SYNOPSIS
Inputs a JSON file and writes it to an OMS Workspace.
.DESCRIPTION
Given a  value pair hash table, this function will write the data to an OMS Log Analytics workspace
Certain variables, such as Customer ID and Shared Key are specific to the OMS workspace data is being written to.
This function will not write to multiple OMS workspaces.  Build-signature and post-analytics function from Microsoft documentation
at https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api
.PARAMETER DateTime
date and time stamp for log.  DateTime value
.PARAMETER Type
Name of the logfile or Log Analytics "Type".  Log Analytics will append _CL at the end of custom logs  String Value
.PARAMETER LogData
A series of key, value pairs that will be written to the log.  Log file are unstructured but the key should be consistent
withing each Log Analytics Type.
.INPUTS
The parameters of data and time, type and logdata.  Logdata is converted to JSON to submit to Log Analytics.
.OUTPUTS
The Function will return the HTTP status code from the Post method.  Status code 200 indicates the request was received.
.NOTES
Version:        2.0
Author:         Travis Roberts
Creation Date:  7/9/2018
Purpose/Change: Crating a stand alone function.
.EXAMPLE
TBD
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [datetime]$dateTime,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$type,
        [Parameter(Mandatory = $true, Position = 2)]
        [Hashtable]$logdata
    )
    Write-Verbose -Message "DateTime: $dateTime"
    Write-Verbose -Message ('DateTimeKind:' + $dateTime.kind)
    Write-Verbose -Message "Type: $type"
    write-Verbose -Message "LogData: $logdata"

    # Check if time is UTC, change to UTC if not.

    if ($dateTime.kind.tostring() -ne 'Utc'){
        $dateTime = $dateTime.ToUniversalTime()
        Write-Verbose -Message "UTC DateTime $dateTime"
    }

    # Supporting Functions
    # Function to create the auth signature
    function Build-signature ($CustomerID, $SharedKey, $Date, $ContentLength, $method, $ContentType, $resource) {
        $xheaders = 'x-ms-date:' + $Date
        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
        $bytesToHash = [text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($SharedKey)
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.key = $keyBytes
        $calculateHash = $sha256.ComputeHash($bytesToHash)
        $encodeHash = [convert]::ToBase64String($calculateHash)
        $authorization = 'SharedKey {0}:{1}' -f $CustomerID,$encodeHash
        return $authorization
    }
    # Function to create and post the request
    Function Post-LogAnalyticsData ($CustomerID, $SharedKey, $Body, $Type) {
        $method = "POST"
        $ContentType = 'application/json'
        $resource = '/api/logs'
        $rfc1123date = ($dateTime).ToString('r')
        $ContentLength = $Body.Length
        $signature = Build-signature `
            -customerId $CustomerID `
            -sharedKey $SharedKey `
            -date $rfc1123date `
            -contentLength $ContentLength `
            -method $method `
            -contentType $ContentType `
            -resource $resource
        $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
        $headers = @{
            "Authorization" = $signature;
            "Log-Type" = $type;
            "x-ms-date" = $rfc1123date
            "time-generated-field" = $dateTime
        }
        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $ContentType -Headers $headers -Body $body -UseBasicParsing
        Write-Verbose -message ('Post Function Return Code ' + $response.statuscode)
        return $response.statuscode
    }
    
    # Add DateTime to hashtable
    $logdata.add("DateTime", $dateTime)

    #Build the JSON file
    $logMessage = ConvertTo-Json $logdata
    Write-Verbose -Message $logMessage

    #Submit the data
    $returnCode = Post-LogAnalyticsData -CustomerID $CustomerID -SharedKey $SharedKey -Body ([System.Text.Encoding]::UTF8.GetBytes($logMessage)) -Type $type
    Write-Verbose -Message "Post Statement Return Code $returnCode"
    return $returnCode
}

############################################ Execution #####################################################

# Ping and Log

while ((Get-Date) -lt $ScriptStartTime.AddHours($HoursToRun)) {
    $output2 = @{}
    foreach ($Computer in $Computers) { 
        $PingTime = get-date
        $PingOutput = (((ping -n 1 -w 5000 $Computer | Out-String).Trim()) -replace '\r\n','--') 
        $Success = $PingOutput -match 'time\=(\d*)ms'
        $PingMS = if ($Success) {$Matches[1]} else {0} 
        $Output2 =  @{
            Address         = $Computer 
            Duration        = $PingMS 
            Error           = if ($LASTEXITCODE -ne 0) { 'True' } else { 'False' }
            PingResponse    = $PingOutput
        }
        Write-OMSLogfile -dateTime $PingTime -type $type -logdata $output2
    }

    write-verbose ($count = ($count + 1))
    $FirstRun = $false
    Start-Sleep -Seconds $waitSec
}