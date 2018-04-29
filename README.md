# MalwLess Simulation Tool

## Releases
You can download the latest releases on https://github.com/n0dec/MalwLess/releases

## Requirements
It is necessary to have `sysmon` installed in your system. https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

###### Rule example
```
  "process_create_rule": {
    "enabled": true,
    "source": "Sysmon",
    "category": "Process Create",
    "description": "Activity event based on Process Create category.",
    "payload": {
      "Image": "process.exe",
      "CommandLine": "process.exe --help"
    }
  }
````
| key | values |
| --- | --- |
| `enabled` | If the value is set to `true` the event will be written. If it's set to `false` just ignore the rule. |
