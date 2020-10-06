/*
 * Author:  @n0dec
 * License: GNU General Public License v3.0
 * 
 */

using System;
using System.IO;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace MalwLess
{
	class Program
	{
		public static void Main(string[] args)
		{
			string file_name = null;
			string json_file = null;
			string sysmonpath = Utils.getSysmonPath();
			string productVersion = null;
			
			
			Utils.printHeader();
			
			if(sysmonpath != null){
				productVersion = Utils.getFileVersion(sysmonpath);
				Console.WriteLine("Sysmon version: " + productVersion);
			}else{
				Console.WriteLine("[!] Error: Sysmon not found");
			}

			if(!Utils.isElevated()){
				Console.WriteLine("[!] Run it as Administrator.");
				Environment.Exit(-1);
			}
			
			try{
				if (args.Length == 2 && args[0] == "-r")
				{
					file_name = args[1];
				}
				else if(args.Length == 0){
					file_name = "rule_test.json";
				}
				else
				{
					Console.WriteLine($"Usage: {Path.GetFileName(Environment.GetCommandLineArgs()[0])} [-r configfile.json]");
					return;
				}

				if(!File.Exists(file_name)){
					Console.WriteLine("File {0} not found!", file_name);
					Console.WriteLine("Check the MST default rule set on: https://github.com/n0dec/MalwLess/blob/master/rule_test.json");
					Environment.Exit(-1);
				}

				Console.WriteLine($" Using file '{file_name}'");
				json_file = File.ReadAllText(file_name);

				JObject rule_test = JObject.Parse(json_file);
				JToken sysmon_config = getDefaultConfig("conf\\Sysmon.json");
				JToken powershell_config = getDefaultConfig("conf\\PowerShell.json");
				
				Console.WriteLine("");
				Console.WriteLine("[Rule test file]: " + file_name);
				Console.WriteLine("[Rule test name]: " + rule_test["name"]);
				Console.WriteLine("[Rule test version]: " + rule_test["version"]);
				Console.WriteLine("[Rule test author]: " + rule_test["author"]);
				Console.WriteLine("[Rule test description]: " + rule_test["description"]);
				Console.WriteLine("");
				
				if(!rule_test["rules"].HasValues){
					Console.WriteLine("No rules detected. Exiting...");
					Environment.Exit(-1);
				}
				
				foreach(var rule in rule_test["rules"].Children()){
					Console.WriteLine("[>] Detected rule: " + rule.Path);
					foreach (var properties in rule.Children()){
						if((bool)properties["enabled"] == true){
							Console.WriteLine("... Source: " + properties["source"]);
							Console.WriteLine("... Category: " + properties["category"]);
							Console.WriteLine("... Description: " + properties["description"]);
							switch (properties["source"].ToString())
							{
								case "Sysmon":
									string productMajorVersion = productVersion.Substring(0, productVersion.IndexOf('.'));
									switch (productMajorVersion){
										case "7":
											SysmonClass_v7.WriteSysmonEvent(properties["category"].ToString(), properties["payload"], sysmon_config);
											break;
										case "8":
										case "9":
											SysmonClass_v8.WriteSysmonEvent(properties["category"].ToString(), properties["payload"], sysmon_config);
											break;
										case "10":
											SysmonClass_v10.WriteSysmonEvent(properties["category"].ToString(), properties["payload"], sysmon_config);
											break;
										case "11":
											// As of Sysmon 11.10, the FileCreateStreamHash event includes the 'Contents' field.
											int productMinorVersion = int.Parse(productVersion.Split(new char[] { '.' })[1]);
											if (productMinorVersion >= 10)
											{
												SysmonClass_v11_10.WriteSysmonEvent(properties["category"].ToString(), properties["payload"], sysmon_config);
											}
											else
											{
												SysmonClass_v11.WriteSysmonEvent(properties["category"].ToString(), properties["payload"], sysmon_config);
											}
											break;
										case "12":
											SysmonClass_v12.WriteSysmonEvent(properties["category"].ToString(), properties["payload"], sysmon_config);
											break;
										default:
											Console.WriteLine("[!] Error: Sysmon version not supported.");
											break;
									}
									break;
								case "PowerShell":
									PowerShellClass.WritePowerShellEvent(properties["category"].ToString(), properties["payload"], powershell_config);
									break;
								default:
									Console.WriteLine("... Source not supported");
									break;
							}
						}else{
							Console.WriteLine("... Rule disabled");
						}
					}
				}

			}
			catch(JsonException jsonException){
				Console.WriteLine("[!] Error with json file: " + jsonException.Message);
				Environment.Exit(-1);
			}catch(Exception e){
				Console.WriteLine("[!] Error: " + e.StackTrace);
				Environment.Exit(-1);
			}
		}
		
		public static JToken getDefaultConfig(string filename){
			if (!File.Exists(filename)){
				Console.WriteLine("[!] Error: File {0} not found.", filename);
			}
			return JToken.Parse(File.ReadAllText(filename));
		}
		
	}
}
