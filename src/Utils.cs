/*
 * Author:	@n0dec
 * License:	GNU General Public License v3.0
 * 
 */
 
using System;
using System.Net;
using System.Net.Sockets;

namespace MalwLess
{

	public static class Utils
	{
		
		public static void printHeader(){
			const string header = @"
			MalwLess Simulation Tool v0.1
			Author: @n0dec
			Site: https://github.com/n0dec/MalwLess
			";
			Console.WriteLine(header.Replace("\t", ""));
		}
		
		public static bool isElevated(){
			return (new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
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
