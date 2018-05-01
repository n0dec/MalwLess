/*
 * Author:	@n0dec
 * License:	GNU General Public License v3.0
 * 
 */
 
using System;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace MalwLess
{
	class Program
	{
		public static void Main(string[] args)
		{
			string file_name = "";
			string json_file = "";
			
			Utils.printHeader();
			
			if(!Utils.isElevated()){
				Console.WriteLine("[!] Run it as Administrator.");
				Environment.Exit(-1);
			}
			
			try{
				if (args.Length == 0){
					file_name = "rule_test.json";
				}else{
					if(args[0] == "-r"){
						file_name = args[1];
					}
				}
				if(File.Exists(file_name)){
					json_file = File.ReadAllText(file_name);
				}else{
					Console.WriteLine("File not found!");
					Console.WriteLine("Check the MST default rule set on: https://github.com/n0dec/MalwLess/blob/master/rule_test.json");
					Environment.Exit(-1);
				}
				
				JObject rule_test = JObject.Parse(json_file);
				JToken config = getDefaultConfig();
				
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
									SysmonClass.WriteSysmonEvent(properties["category"].ToString(), properties["payload"], config);
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
				Console.WriteLine("Error with json file: " + jsonException.Message);
				Environment.Exit(-1);
			}catch(Exception e){
				Console.WriteLine("Error: " + e.StackTrace);
				Environment.Exit(-1);
			}
		}
		
		public static JToken getDefaultConfig(){
			
			string json_config = File.ReadAllText("conf\\config.json");				
			JToken config = JToken.Parse(json_config);			
			return config;
		}
	}
}