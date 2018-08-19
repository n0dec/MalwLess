/*
 * Author:  @n0dec
 * License: GNU General Public License v3.0
 * 
 */
 
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;

namespace MalwLess
{

	public static class Utils
	{
		
		public static void printHeader(){
			
			string version = (Assembly.GetEntryAssembly().GetName().Version).ToString();
			string header = String.Format(@"
			MalwLess Simulation Tool v{0}
			Author: @n0dec
			Site: https://github.com/n0dec/MalwLess
			", version.Substring(0,version.IndexOf('.', version.IndexOf('.') + 1)));
			
			Console.WriteLine(header.Replace("\t", ""));
		}
		
		public static bool isElevated(){
			return (new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
		}
		
		public static string getFileVersion(string filepath){
			return FileVersionInfo.GetVersionInfo(filepath).ProductVersion;
		}
		
		public static string getUtcTime(double seconds){
			return DateTime.Now.AddSeconds(seconds).ToString("yyyy-MM-dd HH:mm:ss.FFF");
		}
		
		public static string getUser(){
			return System.Security.Principal.WindowsIdentity.GetCurrent().Name;
		}
		
		public static string getSourceIp(){
			string result = "127.0.0.1";
			IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
			foreach (IPAddress ip in host.AddressList){
				if(ip.AddressFamily == AddressFamily.InterNetwork){
					result = ip.ToString();
				}
			}
			return result;
		}
		
		public static string getSourceHostname(){
			return Dns.GetHostEntry("localhost").HostName;
		}
		
	}
}
