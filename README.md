# MalwLess Simulation Tool (MST)
`MalwLess` is a open source tool developed in C# for blue teams that allows you to test your SIEM and security systems. Basically you can simulate the behaviour of a malicious attack or system compromise **without the need to run processes or exploits in the network**. It provides a framework based on rules that anyone can write, so when a new technique or attack comes out you can write your own `rules` and share it a with the community.

These rules are parsed and written directly to the Windows EventLog.

## Releases
You can download the latest release on https://github.com/n0dec/MalwLess/releases

## Usage
#### Requirements
It is necessary to have `sysmon` installed in your system. https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

#### Commands
When you have downloaded the latest `release` version you can run it directly from an elevated command prompt.

To test the default `rule set` which is on [`rule_test.json`](https://github.com/n0dec/MalwLess/blob/master/rule_test.json) just download it and run:
```commandline
> malwless.exe
```
If you want to test a different `rule set` file, use the `-r` parameter:
```commandline
> malwless.exe -r your_pack.json
```
To write a custom `rule set` check the [writing sets](https://github.com/n0dec/MalwLess/blob/master/WRITING.md) section.
#### Output
```
MalwLess Simulation Tool v1.0
Author: @n0dec
Site: https://github.com/n0dec/MalwLess

[Rule test file]: rule_test.json
[Rule test name]: MalwLess default
[Rule test version]: 0.1
[Rule test author]: n0dec
[Rule test description]: MalwLess default test pack

[>] Detected rule: rules.rule1
... Source: Sysmon
... Category: Process Create
... Description: Description for rule1
```

## Creating rules
Anyone can create a rule. These are written in `json` with an easy format.

| key | values |
| --- | --- |
| `enabled` | If the value is set to `true` the event will be written. If it's set to `false` just ignore the rule. |
| `source` | The source of the events. (Currently only Sysmon is supported)<br>`Sysmon` |
| `category` | For each source there are a list of different categories that can be specified. |
| `description` | A simple rule description. |
| `payload` | These are the values that will be added to the event. If you don't indicate a specific payload the event will contain the values of the default configuration file located on `conf/config.json`. |

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
```
## Sets
* Windows oneliners [`windows-oneliners.json`](https://github.com/n0dec/MalwLess/blob/master/sets/windows-oneliners.json) Ref: https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/
* [`APTSimulator set`](https://github.com/n0dec/MalwLess/tree/master/sets/APTsimulator) Ref: https://github.com/NextronSystems/APTSimulator
