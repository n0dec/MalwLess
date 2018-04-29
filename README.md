# MalwLess Simulation Tool

## Requirements
It is necessary to have `sysmon` installed. https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

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
