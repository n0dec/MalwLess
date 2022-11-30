﻿using System;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

namespace MalwLess
{

	public static class SysmonClass_v14
	{
		public static void WriteSysmonEvent(string category, JToken payload, JToken config)
		{
			switch(category)
			{
				case "Error report":
					writeErrorReport(payload, config);
					break;
				case "Process Create":
					writeProcessCreate(payload, config);
					break;
				case "File creation time changed":
					writeFileCreateTime(payload, config);
					break;
				case "Network connection detected":
					writeNetworkConnect(payload, config);
					break;
				case "Sysmon service state changed":
					writeServiceStateChanged(payload, config);
					break;
				case "Process terminated":
					writeProcessTerminate(payload, config);
					break;
				case "Driver loaded":
					writeDriverLoad(payload, config);
					break;
				case "Image loaded":
					writeImageLoad(payload, config);
					break;
				case "CreateRemoteThread detected":
					writeCreateRemoteThread(payload, config);
					break;
				case "RawAccessRead detected":
					writeRawAccessRead(payload, config);
					break;
				case "Process accessed":
					writeProcessAccess(payload, config);
					break;
				case "File created":
					writeFileCreate(payload, config);
					break;
				case "Registry object added or deleted":
					writeRegistryEventRegKey(payload, config);
					break;
				case "Registry value set":
					writeRegistryEventRegSetValue(payload, config);
					break;
				case "Registry object renamed":
					writeRegistryEventRegName(payload, config);
					break;
				case "File stream created":
					writeFileCreateStreamHash(payload, config);
					break;
				case "Sysmon config state changed":
					writeServiceConfigurationChanged(payload, config);
					break;
				case "Pipe Created":
					writePipeEventCreate(payload, config);
					break;
				case "Pipe Connected":
					writePipeEventConnect(payload, config);
					break;
				case "WmiEventFilter activity detected":
					writeWmiEventFilter(payload, config);
					break;
				case "WmiEventConsumer activity detected":
					writeWmiEventConsumer(payload, config);
					break;
				case "WmiEventConsumerToFilter activity detected":
					writeWmiEventBinding(payload, config);
					break;
				case "File Delete":
					writeFileDelete(payload, config);
					break;
				case "Dns query":
					writeDnsEvent(payload, config);
					break;
				case "Clipboard changed":
					writeClipboardEvent(payload, config);
					break;
				default:
					Console.WriteLine("Category not supported");
					break;
			}
		}

		static void writeErrorReport(JToken payload, JToken config){
			
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			string ID = payload.Value<string>("ID") ?? "SysmonError";
			string Description = payload.Value<string>("Description") ?? "Failed";

			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_ERROR_EVENT(UtcTime, ID, Description))
				Console.WriteLine("Error: Writing event");
			
		}
		
		static void writeProcessCreate(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string FileVersion = payload.Value<string>("FileVersion") ?? config["FileVersion"].ToString();
			string Description = payload.Value<string>("Description") ?? config["Description"].ToString();
			string Product = payload.Value<string>("Product") ?? config["Product"].ToString();
			string Company = payload.Value<string>("Company") ?? config["Company"].ToString();
			string OriginalFileName = payload.Value<string>("OriginalFileName") ?? "Test.exe" ?? config["OriginalFileName"].ToString();
			string CommandLine = payload.Value<string>("CommandLine") ?? config["CommandLine"].ToString();
			string CurrentDirectory = payload.Value<string>("CurrentDirectory") ?? config["CurrentDirectory"].ToString();
			string User =  payload.Value<string>("User") ?? Utils.getUser();
			Guid LogonGuid = Guid.Parse(payload.Value<string>("LogonGuid") ?? Guid.NewGuid().ToString());
			long LogonId = Convert.ToInt64(payload.Value<string>("LogonId") ?? config["LogonId"].ToString(), 16);
			uint TerminalSessionId = payload.Value<uint?>("TerminalSessionId") ?? (uint)config["TerminalSessionId"];
			string IntegrityLevel = payload.Value<string>("IntegrityLevel") ?? config["IntegrityLevel"].ToString();
			string Hashes = payload.Value<string>("Hashes") ?? config["Hashes"].ToString();
			Guid ParentProcessGuid = Guid.Parse(payload.Value<string>("ParentProcessGuid") ?? Guid.NewGuid().ToString());
			uint ParentProcessId =  payload.Value<uint?>("ParentProcessId") ?? (uint)config["ParentProcessId"];
			string ParentImage = payload.Value<string>("ParentImage") ?? config["ParentImage"].ToString();
			string ParentCommandLine = payload.Value<string>("ParentCommandLine") ?? config["ParentCommandLine"].ToString();
		
			if (!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_CREATE_PROCESS_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, Image, FileVersion, Description, Product, Company, OriginalFileName, CommandLine, CurrentDirectory, User, LogonGuid, LogonId, TerminalSessionId, IntegrityLevel, Hashes, ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeFileCreateTime(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string TargetFilename = payload.Value<string>("TargetFilename") ?? config["TargetFilename"].ToString();
			string CreationUtcTime = payload.Value<string>("CreationUtcTime") ?? Utils.getUtcTime(-600);
			string PreviousCreationUtcTime = payload.Value<string>("PreviousCreationUtcTime") ?? Utils.getUtcTime(-600);
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_FILE_TIME_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime))
				Console.WriteLine("Error: Writing event");
			
		}
		
		static void writeNetworkConnect(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string User =  payload.Value<string>("User") ?? Utils.getUser();
			string Protocol = payload.Value<string>("Protocol") ?? config["Protocol"].ToString();
			bool Initiated = payload.Value<bool?>("Initiated") ?? (bool)config["Initiated"];
			bool SourceIsIpv6 = payload.Value<bool?>("SourceIsIpv6") ?? (bool)config["SourceIsIpv6"];
			string SourceIp = payload.Value<string>("SourceIp") ?? Utils.getSourceIp();
			string SourceHostname = payload.Value<string>("SourceHostname") ?? Utils.getSourceHostname();
			ushort SourcePort = payload.Value<ushort?>("SourcePort") ?? (ushort)config["SourcePort"];
			string SourcePortName = payload.Value<string>("SourcePortName") ?? "";
			bool DestinationIsIpv6 = payload.Value<bool?>("DestinationIsIpv6") ?? (bool)config["DestinationIsIpv6"];
			string DestinationIp = payload.Value<string>("DestinationIp") ?? Utils.getSourceIp();
			string DestinationHostname = payload.Value<string>("DestinationHostname") ?? config["DestinationHostname"].ToString();
			ushort DestinationPort = payload.Value<ushort?>("DestinationPort") ?? (ushort)config["DestinationPort"];
			string DestinationPortName = payload.Value<string>("DestinationPortName") ?? "";
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_NETWORK_CONNECT_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, Image, User, Protocol, Initiated, SourceIsIpv6, SourceIp, SourceHostname, SourcePort, SourcePortName, DestinationIsIpv6, DestinationIp, DestinationHostname, DestinationPort, DestinationPortName))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeServiceStateChanged(JToken payload, JToken config){
			
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			string State = payload.Value<string>("State") ?? config["State"].ToString();
			string Version =  payload.Value<string>("Version") ?? config["Version"].ToString();
			string SchemaVersion = payload.Value<string>("SchemaVersion") ?? config["SchemaVersion"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_SERVICE_STATE_CHANGE_EVENT(UtcTime, State, Version, SchemaVersion))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeProcessTerminate(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_PROCESS_TERMINATE_EVENT(RuleName, UtcTime,ProcessGuid,ProcessId, Image))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeDriverLoad(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			string ImageLoaded = payload.Value<string>("ImageLoaded") ?? config["ImageLoaded"].ToString();
			string Hashes = payload.Value<string>("Hashes") ?? config["Hashes"].ToString();
			string Signed = payload.Value<string>("Signed") ?? config["Signed"].ToString();
			string Signature = payload.Value<string>("Signature") ?? config["Signature"].ToString();
			string SignatureStatus = payload.Value<string>("SignatureStatus") ?? config["SignatureStatus"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_DRIVER_LOAD_EVENT(RuleName, UtcTime, ImageLoaded,Hashes, Signed, Signature, SignatureStatus))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeImageLoad(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string ImageLoaded = payload.Value<string>("ImageLoaded") ?? config["ImageLoaded"].ToString();
			string FileVersion = payload.Value<string>("FileVersion") ?? config["FileVersion"].ToString();
			string Description = payload.Value<string>("Description") ?? config["Description"].ToString();
			string Product = payload.Value<string>("Product") ?? config["Product"].ToString();
			string Company = payload.Value<string>("Company") ?? config["Company"].ToString();
			string OriginalFileName = payload.Value<string>("OriginalFileName") ?? config["OriginalFileName"].ToString();
			string Hashes = payload.Value<string>("Hashes") ?? config["Hashes"].ToString();
			string Signed = payload.Value<string>("Signed") ?? config["Signed"].ToString();
			string Signature = payload.Value<string>("Signature") ?? config["Signature"].ToString();
			string SignatureStatus = payload.Value<string>("SignatureStatus") ?? config["SignatureStatus"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_IMAGE_LOAD_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, Image, ImageLoaded, FileVersion, Description, Product, Company, OriginalFileName, Hashes, Signed, Signature, SignatureStatus))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeCreateRemoteThread(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid SourceProcessGuid = Guid.Parse(payload.Value<string>("SourceProcessGuid") ?? Guid.NewGuid().ToString());
			uint SourceProcessId = payload.Value<uint?>("SourceProcessId") ?? (uint)config["SourceProcessId"];
			string SourceImage = payload.Value<string>("SourceImage") ?? config["SourceImage"].ToString();
			Guid TargetProcessGuid = Guid.Parse(payload.Value<string>("TargetProcessGuid") ?? Guid.NewGuid().ToString());
			uint TargetProcessId = payload.Value<uint?>("TargetProcessId") ?? (uint)config["TargetProcessId"];
			string TargetImage = payload.Value<string>("TargetImage") ?? config["TargetImage"].ToString();
			uint NewThreadId = payload.Value<uint?>("NewThreadId") ?? (uint)config["NewThreadId"];
			string StartAddress = payload.Value<string>("StartAddress") ?? config["StartAddress"].ToString();
			string StartModule = payload.Value<string>("StartModule") ?? config["StartModule"].ToString();
			string StartFunction = payload.Value<string>("StartFunction") ?? config["StartFunction"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_CREATE_REMOTE_THREAD_EVENT(RuleName, UtcTime, SourceProcessGuid, SourceProcessId, SourceImage, TargetProcessGuid, TargetProcessId, TargetImage, NewThreadId, StartAddress, StartModule, StartFunction))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeRawAccessRead(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string Device = payload.Value<string>("Device") ?? config["Device"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_RAWACCESS_READ_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, Image, Device))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeProcessAccess(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid SourceProcessGUID = Guid.Parse(payload.Value<string>("SourceProcessGUID") ?? Guid.NewGuid().ToString());
			uint SourceProcessId = payload.Value<uint?>("SourceProcessId") ?? (uint)config["SourceProcessId"];
			uint SourceThreadId = payload.Value<uint?>("SourceThreadId") ?? (uint)config["SourceThreadId"];
			string SourceImage = payload.Value<string>("SourceImage") ?? config["SourceImage"].ToString();
			Guid TargetProcessGUID = Guid.Parse(payload.Value<string>("TargetProcessGUID") ?? Guid.NewGuid().ToString());
			uint TargetProcessId = payload.Value<uint?>("TargetProcessId") ?? (uint)config["TargetProcessId"];
			string TargetImage = payload.Value<string>("TargetImage") ?? config["TargetImage"].ToString();
			int GrantedAccess = Convert.ToInt32(payload.Value<string>("GrantedAccess") ?? config["GrantedAccess"].ToString(), 16);
			string CallTrace = payload.Value<string>("CallTrace") ?? config["CallTrace"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_ACCESS_PROCESS_EVENT(RuleName, UtcTime, SourceProcessGUID, SourceProcessId, SourceThreadId, SourceImage, TargetProcessGUID, TargetProcessId, TargetImage, GrantedAccess, CallTrace))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeFileCreate(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string TargetFilename = payload.Value<string>("TargetFilename") ?? config["TargetFilename"].ToString();
			string CreationUtcTime = payload.Value<string>("CreationUtcTime") ?? Utils.getUtcTime(-600);
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_FILE_CREATE_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeRegistryEventRegKey(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string EventType = payload.Value<string>("EventType") ?? "CreateKey";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string TargetObject = payload.Value<string>("TargetObject") ?? config["TargetObject"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_REG_KEY_EVENT(RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeRegistryEventRegSetValue(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string EventType = payload.Value<string>("EventType") ?? "SetValue";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string TargetObject = payload.Value<string>("TargetObject") ?? config["TargetObject"].ToString();
			string Details = payload.Value<string>("Details") ?? config["Details"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_REG_SETVALUE_EVENT(RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject, Details))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeRegistryEventRegName(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string EventType = payload.Value<string>("EventType") ?? "RenameKey";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string TargetObject = payload.Value<string>("TargetObject") ?? config["TargetObject"].ToString();
			string NewName = payload.Value<string>("NewName") ?? config["NewName"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_REG_NAME_EVENT(RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject, NewName))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeFileCreateStreamHash(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string TargetFilename = payload.Value<string>("TargetFilename") ?? config["TargetFilename"].ToString();
			string CreationUtcTime = payload.Value<string>("CreationUtcTime") ?? Utils.getUtcTime(-600);
			string Hash = payload.Value<string>("Hash") ?? config["Hash"].ToString();
			string Contents = payload.Value<string>("Contents") ?? config["Contents"].ToString();
			
			if (!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_FILE_CREATE_STREAM_HASH_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime, Hash, Contents))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeServiceConfigurationChanged(JToken payload, JToken config){
			
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			string Configuration = payload.Value<string>("Configuration") ?? config["Configuration"].ToString();
			string ConfigurationFileHash =  payload.Value<string>("ConfigurationFileHash") ?? config["ConfigurationFileHash"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_SERVICE_CONFIGURATION_CHANGE_EVENT(UtcTime, Configuration, ConfigurationFileHash))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writePipeEventCreate(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string EventType = payload.Value<string>("EventType") ?? "CreatePipe";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string PipeName = payload.Value<string>("PipeName") ?? config["PipeName"].ToString();
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_CREATE_NAMEDPIPE_EVENT(RuleName, EventType, UtcTime, ProcessGuid, ProcessId, PipeName, Image))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writePipeEventConnect(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string EventType = payload.Value<string>("EventType") ?? "ConnectPipe";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string PipeName = payload.Value<string>("PipeName") ?? config["PipeName"].ToString();
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_CONNECT_NAMEDPIPE_EVENT(RuleName, EventType, UtcTime, ProcessGuid, ProcessId, PipeName, Image))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeWmiEventFilter(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string EventType = payload.Value<string>("EventType") ?? "WmiFilterEvent";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			string Operation = payload.Value<string>("Operation") ?? config["Operation"].ToString();
			string User =  payload.Value<string>("User") ?? Utils.getUser();
			string EventNamespace = payload.Value<string>("EventNamespace") ?? config["EventNamespace"].ToString();
			string Name = payload.Value<string>("Name") ?? config["Name"].ToString();
			string Query = payload.Value<string>("Query") ?? config["Query"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_WMI_FILTER_EVENT(RuleName, EventType, UtcTime, Operation, User, EventNamespace, Name, Query))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeWmiEventConsumer(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string EventType = payload.Value<string>("EventType") ?? "WmiConsumerEvent";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			string Operation = payload.Value<string>("Operation") ?? config["Operation"].ToString();
			string User =  payload.Value<string>("User") ?? Utils.getUser();
			string Name = payload.Value<string>("Name") ?? config["Name"].ToString();
			string Type = payload.Value<string>("Type") ?? config["Type"].ToString();
			string Destination = payload.Value<string>("Destination") ?? config["Destination"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_WMI_CONSUMER_EVENT(RuleName, EventType, UtcTime, Operation, User, Name, Type, Destination))
				Console.WriteLine("Error: Writing event");
		}
		
		static void writeWmiEventBinding(JToken payload, JToken config){
			
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string EventType = payload.Value<string>("EventType") ?? "WmiBindingEvent";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			string Operation = payload.Value<string>("Operation") ?? config["Operation"].ToString();
			string User =  payload.Value<string>("User") ?? Utils.getUser();
			string Consumer = payload.Value<string>("Consumer") ?? config["Consumer"].ToString();
			string Filter = payload.Value<string>("Filter") ?? config["Filter"].ToString();
			
			if(!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_WMI_BINDING_EVENT(RuleName, EventType, UtcTime, Operation, User, Consumer, Filter))
				Console.WriteLine("Error: Writing event");
		}

		private static void writeFileDelete(JToken payload, JToken config)
		{
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string User = payload.Value<string>("User") ?? Utils.getUser();
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();
			string TargetFilename = payload.Value<string>("TargetFilename") ?? config["TargetFilename"].ToString();
			string Hashes = payload.Value<string>("Hashes") ?? config["Hashes"].ToString();
			bool IsExecutable = payload.Value<bool?>("IsExecutable") ?? (bool)config["IsExecutable"];
			string Archived = payload.Value<string>("Archived") ?? config["Archived"].ToString();

			if (!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_FILE_DELETE_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, User, Image, TargetFilename, Hashes, IsExecutable, Archived))
				Console.WriteLine("Error: Writing event");
		}

		static void writeDnsEvent(JToken payload, JToken config)
		{
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string QueryName = payload.Value<string>("QueryName") ?? "";
			string QueryStatus = payload.Value<string>("QueryStatus") ?? "";
			string QueryResults = payload.Value<string>("QueryResults") ?? "";
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();

			if (!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_DNS_QUERY_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, QueryName, QueryStatus, QueryResults, Image))
				Console.WriteLine("Error: Writing event");
		}

		static void writeClipboardEvent(JToken payload, JToken config)
		{
			string RuleName = payload.Value<string>("RuleName") ?? "";
			string UtcTime = payload.Value<string>("UtcTime") ?? Utils.getUtcTime(0);
			Guid ProcessGuid = Guid.Parse(payload.Value<string>("ProcessGuid") ?? Guid.NewGuid().ToString());
			uint ProcessId = payload.Value<uint?>("ProcessId") ?? (uint)config["ProcessId"];
			string Image = payload.Value<string>("Image") ?? config["Image"].ToString();

			uint Session = payload.Value<uint?>("Session") ?? (uint)config["Session"];
			string ClientInfo = payload.Value<string>("ClientInfo") ?? config["ClientInfo"].ToString();
			string Hashes = payload.Value<string>("Hashes") ?? config["Hashes"].ToString();
			string Archived = payload.Value<string>("Archived") ?? config["Archived"].ToString();

			if (!Sysmon_v14.Namespace.SYSMON_PROVIDER_V14.EventWriteSYSMON_CLIPBOARD_EVENT(RuleName, UtcTime, ProcessGuid, ProcessId, Image, Session, ClientInfo, Hashes, Archived))
				Console.WriteLine("Error: Writing event");
		}
	}
}
