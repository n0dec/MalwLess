# MalwLess Simulation Tool (MST)
`MalwLess` is an open source tool that allows you to simulate system compromise or attack behaviours without running processes or PoCs. The tool is designed to test Blue Team detections and SIEM correlation rules. It provides a framework based on rules that anyone can write, so when a new technique or attack comes out you can write your own rules and share it a with the community.

These rules can simulate [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) or [PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/getting-started/getting-started-with-windows-powershell) events. `MalwLess` can parse the rules and write them directly to the Windows EventLog, then you can foward it to your event collector.

```
MalwLess Simulation Tool v1.1
Author: @n0dec
Site: https://github.com/n0dec/MalwLess

[Rule test file]: rule_test.json
[Rule test name]: MalwLess default
[Rule test version]: 0.3
[Rule test author]: n0dec
[Rule test description]: MalwLess default test pack.

[>] Detected rule: rules.vssadmin_delete_shadows
... Source: Sysmon
... Category: Process Create
... Description: Deleted shadows copies via vssadmin.
[>] Detected rule: rules.certutil_network_activity
... Source: Sysmon
... Category: Network connection detected
... Description: Network activity from certutil tool.
[>] Detected rule: rules.powershell_scriptblock
... Source: PowerShell
... Category: 4104
... Description: Powershell 4104 event for Invoke-Mimikatz.
```

![schema](https://camo.githubusercontent.com/5c39cb73c6f44458916f18e9f51e5af0894a3d78/68747470733a2f2f692e696d6775722e636f6d2f4832546631334d2e706e67)

## Download
You can download the latest release from website https://n0dec.github.io/#malwless
or from releases section https://github.com/n0dec/MalwLess/releases - This release is however incompatible with the newest Sysmon versions (from Sysmon 13 upwards).

Executable version of Malwless working with the newest Sysmon versions can be found in 'Malwless-Modified-exe' directory, inside this repository.

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

## Creating rules
Anyone can create a rule. These are written in `json` with an easy format.
Additionally you can parse raw events and convert it to rule using [converter](https://n0dec.github.io/#rules)

| key | values |
| --- | --- |
| `enabled` | If the value is set to `true` the event will be written. If it's set to `false` just ignore the rule. |
| `source` | `Sysmon`<br>`PowerShell` |
| `category` | For each source there are a list of different categories that can be specified. |
| `description` | A simple rule description. |
| `payload` | These are the values that will be added to the event. If you don't indicate a specific payload the event will contain the values of the default configuration files located on `conf`. |

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
* [`Mitre ATT&CK`](https://github.com/n0dec/MalwLess/tree/master/sets/ATT%26CK) ref: https://attack.mitre.org/
* [`APTSimulator set`](https://github.com/n0dec/MalwLess/tree/master/sets/APTSimulator) ref: https://github.com/NextronSystems/APTSimulator
* [`Endgame RTA set`](https://github.com/n0dec/MalwLess/tree/master/sets/EndgameRTA) ref: https://github.com/endgameinc/RTA
* [`Windows oneliners`](https://github.com/n0dec/MalwLess/blob/master/sets/windows-oneliners.json) ref: https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/
* [`WinPwnage set`](https://github.com/n0dec/MalwLess/tree/master/sets/WinPwnage) ref: https://github.com/rootm0s/WinPwnage
* [`Awesome gists sets`](https://github.com/n0dec/MalwLess/blob/master/GISTS.md)

## Contact
For any issue or suggestions contact me on twitter [@n0dec](https://twitter.com/n0dec).

Website: https://n0dec.github.io

