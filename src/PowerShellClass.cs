/*
 * Author:  @n0dec
 * License: GNU General Public License v3.0
 * 
 */

namespace MalwLess
{
using System;
using Newtonsoft.Json.Linq;

	public static class PowerShellClass
	{
		public static void WritePowerShellEvent(string category, JToken payload, JToken config)
		{
			switch(category)
			{
				case "4103":
					writeEventID_4103(payload, config);
					break;
				case "4104":
					writeEventID_4104(payload, config);
					break;
				default:
					Console.WriteLine("Category not supported");
					break;
			}
		}
		
		static void writeEventID_4103(JToken payload, JToken config){
			string ContextInfo = payload.Value<string>("ContextInfo") ?? config["ContextInfo"].ToString();
			string UserData = payload.Value<string>("UserData") ?? config["UserData"].ToString();
			string Payload = payload.Value<string>("Payload") ?? config["Payload"].ToString();
			
			if(!PowerShell.Namespace.MicrosoftWindowsPowerShell_PROVIDER.EventWriteEventID_4103(ContextInfo, UserData, Payload))
				Console.WriteLine("Error: Writing event");
			
		}
		
		static void writeEventID_4104(JToken payload, JToken config){
			int MessageNumber = payload.Value<int?>("MessageNumber") ?? (int)config["MessageNumber"];;
			int MessageTotal = payload.Value<int?>("MessageTotal") ?? (int)config["MessageTotal"];;
			string ScriptBlockText = payload.Value<string>("ScriptBlockText") ?? config["ScriptBlockText"].ToString();
			string ScriptBlockId = payload.Value<string>("ScriptBlockId") ?? config["ScriptBlockId"].ToString();
			string Path = payload.Value<string>("Path") ?? config["Path"].ToString();
			
			if(!PowerShell.Namespace.MicrosoftWindowsPowerShell_PROVIDER.EventWriteEventID_4104(MessageNumber, MessageTotal, ScriptBlockText, ScriptBlockId, Path))
				Console.WriteLine("Error: Writing event");
			
		}
	}
}
