# Detecting TeamsPhisher 
## Hunt Tags


## Topic intro
* 

## Detection description


### KQL

**KQL query:**

```C#
// Baseline of common SharePoint domains observerd in organisation/Allow list
let SenderSharepointDomainBaseline = datatable (SenderSharepointDomainName:string)[
    "test.sharepoint.com" // 
];
DeviceProcessEvents
| where InitiatingProcessFileName == "Teams.exe" and InitiatingProcessCommandLine !contains "https://teams.microsoft.com/l/meetup-join"
| parse-where ProcessCommandLine with * "--single-argument " OneDriveSuspiciousURL
//| where OneDriveSuspiciousURL !contains "ORGTENANTNAME.sharepoint.com" //whitelisting organisation sharepoint pages
//| where OneDriveSuspiciousURL !contains "ORGTENANTNAME-my.sharepoint.com" 
| where OneDriveSuspiciousURL !contains "statics.teams.cdn."
| where OneDriveSuspiciousURL contains "sharepoint.com" / enterprise sharepoint with Azure AD, used by TeamsPhisher tool 
  or OneDriveSuspiciousURL startswith "https://1drv.ms" / private sharepoint, phishing from non enterprise accounts like gmail etc.
| extend URLParsed = parse_url(OneDriveSuspiciousURL)
| extend SenderSharepointDomain = tostring(URLParsed.Host)
| where SenderSharepointDomain !in (SenderSharepointDomainBaseline)
| extend MSTeamsClickTime=TimeGenerated
| join (DeviceFileEvents
    | where isnotempty(SHA256)
    | where ActionType == "FileRenamed"
    and PreviousFileName endswith ".crdownload"
    | extend FileDownloadTime=TimeGenerated
    )
    on DeviceId and $left.InitiatingProcessAccountSid == $right.RequestAccountSid and InitiatingProcessAccountUpn and $left.FileName == $right.InitiatingProcessFileName
    | where (FileDownloadTime - MSTeamsClickTime) between (0min .. 2min)
| extend
    MSTeamsClickTime = TimeGenerated, 
    BrowserOneDriveDownloadTime = TimeGenerated1,
    InitiatingParentProcessFileName = InitiatingProcessFileName,
    InitiatingProcessFileName = InitiatingProcessFileName1,
    FilePath = FolderPath1,
    DownloadedFile = FileName1 
| project
    MSTeamsClickTime,
    BrowserOneDriveDownloadTime,
    DeviceName,
    InitiatingProcessAccountUpn,
    InitiatingParentProcessFileName,
    InitiatingProcessFileName,
    OneDriveSuspiciousURL,
    FilePath,
    DownloadedFile
| extend URLParsed = parse_url(OneDriveSuspiciousURL)
| extend SenderSharepointDomain = tostring(URLParsed.Host)
| where SenderSharepointDomain !in (SenderSharepointDomainBaseline)


```


## References
* 