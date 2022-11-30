﻿namespace Sysmon_v14.Namespace
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Diagnostics;
    using System.Diagnostics.Eventing;
    using Microsoft.Win32;
    using System.Runtime.InteropServices;
    using System.Security.Principal;

    public static class SYSMON_PROVIDER_V14
    {
        //
        // Provider "Microsoft-Windows-Sysmon" event count = 25
        //

        internal static EventProviderVersionTwo m_provider = new EventProviderVersionTwo(new Guid("5770385f-c22a-43e0-bf4c-06f5698ffbd9"));
        //
        // Task :  eventGUIDs
        //
        private static Guid SysmonTask_SYSMON_ERRORId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee000000ff");
        private static Guid SysmonTask_SYSMON_CREATE_PROCESSId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000001");
        private static Guid SysmonTask_SYSMON_FILE_TIMEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000002");
        private static Guid SysmonTask_SYSMON_NETWORK_CONNECTId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000003");
        private static Guid SysmonTask_SYSMON_SERVICE_STATE_CHANGEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000004");
        private static Guid SysmonTask_SYSMON_PROCESS_TERMINATEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000005");
        private static Guid SysmonTask_SYSMON_DRIVER_LOADId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000006");
        private static Guid SysmonTask_SYSMON_IMAGE_LOADId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000007");
        private static Guid SysmonTask_SYSMON_CREATE_REMOTE_THREADId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000008");
        private static Guid SysmonTask_SYSMON_RAWACCESS_READId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000009");
        private static Guid SysmonTask_SYSMON_ACCESS_PROCESSId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee0000000a");
        private static Guid SysmonTask_SYSMON_FILE_CREATEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee0000000b");
        private static Guid SysmonTask_SYSMON_REG_KEYId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee0000000c");
        private static Guid SysmonTask_SYSMON_REG_SETVALUEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee0000000d");
        private static Guid SysmonTask_SYSMON_REG_NAMEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee0000000e");
        private static Guid SysmonTask_SYSMON_FILE_CREATE_STREAM_HASHId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee0000000f");
        private static Guid SysmonTask_SYSMON_SERVICE_CONFIGURATION_CHANGEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000010");
        private static Guid SysmonTask_SYSMON_CREATE_NAMEDPIPEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000011");
        private static Guid SysmonTask_SYSMON_CONNECT_NAMEDPIPEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000012");
        private static Guid SysmonTask_SYSMON_WMI_FILTERId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000013");
        private static Guid SysmonTask_SYSMON_WMI_CONSUMERId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000014");
        private static Guid SysmonTask_SYSMON_WMI_BINDINGId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000015");
        private static Guid SysmonTask_SYSMON_DNS_QUERYId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000016");
        private static Guid SysmonTask_SYSMON_FILE_DELETEId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000017");
        private static Guid SysmonTask_SYSMON_CLIPBOARDId = new Guid("c511ffb3-9fbf-45f5-a97b-9bee00000018");

        //
        // Event Descriptors
        //
        private static EventDescriptor SYSMON_ERROR_EVENT;
        private static EventDescriptor SYSMON_CREATE_PROCESS_EVENT;
        private static EventDescriptor SYSMON_FILE_TIME_EVENT;
        private static EventDescriptor SYSMON_NETWORK_CONNECT_EVENT;
        private static EventDescriptor SYSMON_SERVICE_STATE_CHANGE_EVENT;
        private static EventDescriptor SYSMON_PROCESS_TERMINATE_EVENT;
        private static EventDescriptor SYSMON_DRIVER_LOAD_EVENT;
        private static EventDescriptor SYSMON_IMAGE_LOAD_EVENT;
        private static EventDescriptor SYSMON_CREATE_REMOTE_THREAD_EVENT;
        private static EventDescriptor SYSMON_RAWACCESS_READ_EVENT;
        private static EventDescriptor SYSMON_ACCESS_PROCESS_EVENT;
        private static EventDescriptor SYSMON_FILE_CREATE_EVENT;
        private static EventDescriptor SYSMON_REG_KEY_EVENT;
        private static EventDescriptor SYSMON_REG_SETVALUE_EVENT;
        private static EventDescriptor SYSMON_REG_NAME_EVENT;
        private static EventDescriptor SYSMON_FILE_CREATE_STREAM_HASH_EVENT;
        private static EventDescriptor SYSMON_SERVICE_CONFIGURATION_CHANGE_EVENT;
        private static EventDescriptor SYSMON_CREATE_NAMEDPIPE_EVENT;
        private static EventDescriptor SYSMON_CONNECT_NAMEDPIPE_EVENT;
        private static EventDescriptor SYSMON_WMI_FILTER_EVENT;
        private static EventDescriptor SYSMON_WMI_CONSUMER_EVENT;
        private static EventDescriptor SYSMON_WMI_BINDING_EVENT;
        private static EventDescriptor SYSMON_DNS_QUERY_EVENT;
        private static EventDescriptor SYSMON_FILE_DELETE_EVENT;
        private static EventDescriptor SYSMON_CLIPBOARD_EVENT;

        static SYSMON_PROVIDER_V14()
        {
            unchecked
            {
                SYSMON_ERROR_EVENT = new EventDescriptor(0xff, 0x3, 0x10, 0x2, 0x0, 0xff, (long)0x8000000000000000);
                SYSMON_CREATE_PROCESS_EVENT = new EventDescriptor(0x1, 0x5, 0x10, 0x4, 0x0, 0x1, (long)0x8000000000000000);
                SYSMON_FILE_TIME_EVENT = new EventDescriptor(0x2, 0x5, 0x10, 0x4, 0x0, 0x2, (long)0x8000000000000000);
                SYSMON_NETWORK_CONNECT_EVENT = new EventDescriptor(0x3, 0x5, 0x10, 0x4, 0x0, 0x3, (long)0x8000000000000000);
                SYSMON_SERVICE_STATE_CHANGE_EVENT = new EventDescriptor(0x4, 0x3, 0x10, 0x4, 0x0, 0x4, (long)0x8000000000000000);
                SYSMON_PROCESS_TERMINATE_EVENT = new EventDescriptor(0x5, 0x3, 0x10, 0x4, 0x0, 0x5, (long)0x8000000000000000);
                SYSMON_DRIVER_LOAD_EVENT = new EventDescriptor(0x6, 0x4, 0x10, 0x4, 0x0, 0x6, (long)0x8000000000000000);
                SYSMON_IMAGE_LOAD_EVENT = new EventDescriptor(0x7, 0x3, 0x10, 0x4, 0x0, 0x7, (long)0x8000000000000000);
                SYSMON_CREATE_REMOTE_THREAD_EVENT = new EventDescriptor(0x8, 0x2, 0x10, 0x4, 0x0, 0x8, (long)0x8000000000000000);
                SYSMON_RAWACCESS_READ_EVENT = new EventDescriptor(0x9, 0x2, 0x10, 0x4, 0x0, 0x9, (long)0x8000000000000000);
                SYSMON_ACCESS_PROCESS_EVENT = new EventDescriptor(0xa, 0x3, 0x10, 0x4, 0x0, 0xa, (long)0x8000000000000000);
                SYSMON_FILE_CREATE_EVENT = new EventDescriptor(0xb, 0x2, 0x10, 0x4, 0x0, 0xb, (long)0x8000000000000000);
                SYSMON_REG_KEY_EVENT = new EventDescriptor(0xc, 0x2, 0x10, 0x4, 0x0, 0xc, (long)0x8000000000000000);
                SYSMON_REG_SETVALUE_EVENT = new EventDescriptor(0xd, 0x2, 0x10, 0x4, 0x0, 0xd, (long)0x8000000000000000);
                SYSMON_REG_NAME_EVENT = new EventDescriptor(0xe, 0x2, 0x10, 0x4, 0x0, 0xe, (long)0x8000000000000000);
                SYSMON_FILE_CREATE_STREAM_HASH_EVENT = new EventDescriptor(0xf, 0x2, 0x10, 0x4, 0x0, 0xf, (long)0x8000000000000000);
                SYSMON_SERVICE_CONFIGURATION_CHANGE_EVENT = new EventDescriptor(0x10, 0x3, 0x10, 0x4, 0x0, 0x10, (long)0x8000000000000000);
                SYSMON_CREATE_NAMEDPIPE_EVENT = new EventDescriptor(0x11, 0x1, 0x10, 0x4, 0x0, 0x11, (long)0x8000000000000000);
                SYSMON_CONNECT_NAMEDPIPE_EVENT = new EventDescriptor(0x12, 0x1, 0x10, 0x4, 0x0, 0x12, (long)0x8000000000000000);
                SYSMON_WMI_FILTER_EVENT = new EventDescriptor(0x13, 0x3, 0x10, 0x4, 0x0, 0x13, (long)0x8000000000000000);
                SYSMON_WMI_CONSUMER_EVENT = new EventDescriptor(0x14, 0x3, 0x10, 0x4, 0x0, 0x14, (long)0x8000000000000000);
                SYSMON_WMI_BINDING_EVENT = new EventDescriptor(0x15, 0x3, 0x10, 0x4, 0x0, 0x15, (long)0x8000000000000000);
                SYSMON_DNS_QUERY_EVENT = new EventDescriptor(0x16, 0x5, 0x10, 0x4, 0x0, 0x16, (long)0x8000000000000000);
                SYSMON_FILE_DELETE_EVENT = new EventDescriptor(0x17, 0x5, 0x10, 0x4, 0x0, 0x17, (long)0x8000000000000000);
                SYSMON_CLIPBOARD_EVENT = new EventDescriptor(0x18, 0x5, 0x10, 0x4, 0x0, 0x18, (long)0x8000000000000000);
            }
        }

        //
        // Event method for SYSMON_ERROR_EVENT
        //
        public static bool EventWriteSYSMON_ERROR_EVENT(string UtcTime, string ID, string Description)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateError_report(ref SYSMON_ERROR_EVENT, UtcTime, ID, Description);
        }

        //
        // Event method for SYSMON_CREATE_PROCESS_EVENT
        //
        public static bool EventWriteSYSMON_CREATE_PROCESS_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string FileVersion, string Description, string Product, string Company, string OriginalFileName, string CommandLine, string CurrentDirectory, string User, Guid LogonGuid, long LogonId, uint TerminalSessionId, string IntegrityLevel, string Hashes, Guid ParentProcessGuid, uint ParentProcessId, string ParentImage, string ParentCommandLine)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateProcess_Create(ref SYSMON_CREATE_PROCESS_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, Image, FileVersion, Description, Product, Company, OriginalFileName, CommandLine, CurrentDirectory, User, LogonGuid, LogonId, TerminalSessionId, IntegrityLevel, Hashes, ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine);
        }

        //
        // Event method for SYSMON_FILE_TIME_EVENT
        //
        public static bool EventWriteSYSMON_FILE_TIME_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetFilename, string CreationUtcTime, string PreviousCreationUtcTime)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateFile_creation_time_changed(ref SYSMON_FILE_TIME_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime);
        }

        //
        // Event method for SYSMON_NETWORK_CONNECT_EVENT
        //
        public static bool EventWriteSYSMON_NETWORK_CONNECT_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string User, string Protocol, bool Initiated, bool SourceIsIpv6, string SourceIp, string SourceHostname, ushort SourcePort, string SourcePortName, bool DestinationIsIpv6, string DestinationIp, string DestinationHostname, ushort DestinationPort, string DestinationPortName)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateNetwork_connection_detected(ref SYSMON_NETWORK_CONNECT_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, Image, User, Protocol, Initiated, SourceIsIpv6, SourceIp, SourceHostname, SourcePort, SourcePortName, DestinationIsIpv6, DestinationIp, DestinationHostname, DestinationPort, DestinationPortName);
        }

        //
        // Event method for SYSMON_SERVICE_STATE_CHANGE_EVENT
        //
        public static bool EventWriteSYSMON_SERVICE_STATE_CHANGE_EVENT(string UtcTime, string State, string Version, string SchemaVersion)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateSysmon_service_state_changed(ref SYSMON_SERVICE_STATE_CHANGE_EVENT, UtcTime, State, Version, SchemaVersion);
        }

        //
        // Event method for SYSMON_PROCESS_TERMINATE_EVENT
        //
        public static bool EventWriteSYSMON_PROCESS_TERMINATE_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateProcess_terminated(ref SYSMON_PROCESS_TERMINATE_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, Image);
        }

        //
        // Event method for SYSMON_DRIVER_LOAD_EVENT
        //
        public static bool EventWriteSYSMON_DRIVER_LOAD_EVENT(string RuleName, string UtcTime, string ImageLoaded, string Hashes, string Signed, string Signature, string SignatureStatus)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateDriver_loaded(ref SYSMON_DRIVER_LOAD_EVENT, RuleName, UtcTime, ImageLoaded, Hashes, Signed, Signature, SignatureStatus);
        }

        //
        // Event method for SYSMON_IMAGE_LOAD_EVENT
        //
        public static bool EventWriteSYSMON_IMAGE_LOAD_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string ImageLoaded, string FileVersion, string Description, string Product, string Company, string OriginalFileName, string Hashes, string Signed, string Signature, string SignatureStatus)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateImage_loaded(ref SYSMON_IMAGE_LOAD_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, Image, ImageLoaded, FileVersion, Description, Product, Company, OriginalFileName, Hashes, Signed, Signature, SignatureStatus);
        }

        //
        // Event method for SYSMON_CREATE_REMOTE_THREAD_EVENT
        //
        public static bool EventWriteSYSMON_CREATE_REMOTE_THREAD_EVENT(string RuleName, string UtcTime, Guid SourceProcessGuid, uint SourceProcessId, string SourceImage, Guid TargetProcessGuid, uint TargetProcessId, string TargetImage, uint NewThreadId, string StartAddress, string StartModule, string StartFunction)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateCreateRemoteThread_detected(ref SYSMON_CREATE_REMOTE_THREAD_EVENT, RuleName, UtcTime, SourceProcessGuid, SourceProcessId, SourceImage, TargetProcessGuid, TargetProcessId, TargetImage, NewThreadId, StartAddress, StartModule, StartFunction);
        }

        //
        // Event method for SYSMON_RAWACCESS_READ_EVENT
        //
        public static bool EventWriteSYSMON_RAWACCESS_READ_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string Device)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateRawAccessRead_detected(ref SYSMON_RAWACCESS_READ_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, Image, Device);
        }

        //
        // Event method for SYSMON_ACCESS_PROCESS_EVENT
        //
        public static bool EventWriteSYSMON_ACCESS_PROCESS_EVENT(string RuleName, string UtcTime, Guid SourceProcessGUID, uint SourceProcessId, uint SourceThreadId, string SourceImage, Guid TargetProcessGUID, uint TargetProcessId, string TargetImage, int GrantedAccess, string CallTrace)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateProcess_accessed(ref SYSMON_ACCESS_PROCESS_EVENT, RuleName, UtcTime, SourceProcessGUID, SourceProcessId, SourceThreadId, SourceImage, TargetProcessGUID, TargetProcessId, TargetImage, GrantedAccess, CallTrace);
        }

        //
        // Event method for SYSMON_FILE_CREATE_EVENT
        //
        public static bool EventWriteSYSMON_FILE_CREATE_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetFilename, string CreationUtcTime)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateFile_created(ref SYSMON_FILE_CREATE_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime);
        }

        //
        // Event method for SYSMON_REG_KEY_EVENT
        //
        public static bool EventWriteSYSMON_REG_KEY_EVENT(string RuleName, string EventType, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetObject)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateRegistry_object_added_or_deleted(ref SYSMON_REG_KEY_EVENT, RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject);
        }

        //
        // Event method for SYSMON_REG_SETVALUE_EVENT
        //
        public static bool EventWriteSYSMON_REG_SETVALUE_EVENT(string RuleName, string EventType, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetObject, string Details)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateRegistry_value_set(ref SYSMON_REG_SETVALUE_EVENT, RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject, Details);
        }

        //
        // Event method for SYSMON_REG_NAME_EVENT
        //
        public static bool EventWriteSYSMON_REG_NAME_EVENT(string RuleName, string EventType, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetObject, string NewName)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateRegistry_object_renamed(ref SYSMON_REG_NAME_EVENT, RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject, NewName);
        }

        //
        // Event method for SYSMON_FILE_CREATE_STREAM_HASH_EVENT
        //
        public static bool EventWriteSYSMON_FILE_CREATE_STREAM_HASH_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetFilename, string CreationUtcTime, string Hash, string Contents)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateFile_stream_created(ref SYSMON_FILE_CREATE_STREAM_HASH_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime, Hash, Contents);
        }

        //
        // Event method for SYSMON_SERVICE_CONFIGURATION_CHANGE_EVENT
        //
        public static bool EventWriteSYSMON_SERVICE_CONFIGURATION_CHANGE_EVENT(string UtcTime, string Configuration, string ConfigurationFileHash)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateSysmon_config_state_changed(ref SYSMON_SERVICE_CONFIGURATION_CHANGE_EVENT, UtcTime, Configuration, ConfigurationFileHash);
        }

        //
        // Event method for SYSMON_CREATE_NAMEDPIPE_EVENT
        //
        public static bool EventWriteSYSMON_CREATE_NAMEDPIPE_EVENT(string RuleName, string EventType, string UtcTime, Guid ProcessGuid, uint ProcessId, string PipeName, string Image)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplatePipe_Created(ref SYSMON_CREATE_NAMEDPIPE_EVENT, RuleName, EventType, UtcTime, ProcessGuid, ProcessId, PipeName, Image);
        }

        //
        // Event method for SYSMON_CONNECT_NAMEDPIPE_EVENT
        //
        public static bool EventWriteSYSMON_CONNECT_NAMEDPIPE_EVENT(string RuleName, string EventType, string UtcTime, Guid ProcessGuid, uint ProcessId, string PipeName, string Image)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplatePipe_Connected(ref SYSMON_CONNECT_NAMEDPIPE_EVENT, RuleName, EventType, UtcTime, ProcessGuid, ProcessId, PipeName, Image);
        }

        //
        // Event method for SYSMON_WMI_FILTER_EVENT
        //
        public static bool EventWriteSYSMON_WMI_FILTER_EVENT(string RuleName, string EventType, string UtcTime, string Operation, string User, string EventNamespace, string Name, string Query)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateWmiEventFilter_activity_detected(ref SYSMON_WMI_FILTER_EVENT, RuleName, EventType, UtcTime, Operation, User, EventNamespace, Name, Query);
        }

        //
        // Event method for SYSMON_WMI_CONSUMER_EVENT
        //
        public static bool EventWriteSYSMON_WMI_CONSUMER_EVENT(string RuleName, string EventType, string UtcTime, string Operation, string User, string Name, string Type, string Destination)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateWmiEventConsumer_activity_detected(ref SYSMON_WMI_CONSUMER_EVENT, RuleName, EventType, UtcTime, Operation, User, Name, Type, Destination);
        }

        //
        // Event method for SYSMON_WMI_BINDING_EVENT
        //
        public static bool EventWriteSYSMON_WMI_BINDING_EVENT(string RuleName, string EventType, string UtcTime, string Operation, string User, string Consumer, string Filter)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateWmiEventConsumerToFilter_activity_detected(ref SYSMON_WMI_BINDING_EVENT, RuleName, EventType, UtcTime, Operation, User, Consumer, Filter);
        }

        //
        // Event method for SYSMON_DNS_QUERY_EVENT
        //
        public static bool EventWriteSYSMON_DNS_QUERY_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string QueryName, string QueryStatus, string QueryResults, string Image)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateDns_query(ref SYSMON_DNS_QUERY_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, QueryName, QueryStatus, QueryResults, Image);
        }

        //
        // Event method for SYSMON_FILE_DELETE_EVENT
        //
        public static bool EventWriteSYSMON_FILE_DELETE_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string User, string Image, string TargetFilename, string Hashes, bool IsExecutable, string Archived)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateFile_Delete(ref SYSMON_FILE_DELETE_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, User, Image, TargetFilename, Hashes, IsExecutable, Archived);
        }

        //
        // Event method for SYSMON_CLIPBOARD_EVENT
        //
        public static bool EventWriteSYSMON_CLIPBOARD_EVENT(string RuleName, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, uint Session, string ClientInfo, string Hashes, string Archived)
        {
            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateClipboard_changed(ref SYSMON_CLIPBOARD_EVENT, RuleName, UtcTime, ProcessGuid, ProcessId, Image, Session, ClientInfo, Hashes, Archived);
        }
    }

    internal class EventProviderVersionTwo : EventProvider
    {
        internal EventProviderVersionTwo(Guid id)
               : base(id)
        { }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct EventData
        {
            [FieldOffset(0)]
            internal UInt64 DataPointer;
            [FieldOffset(8)]
            internal uint Size;
            [FieldOffset(12)]
            internal int Reserved;
        }

        internal unsafe bool TemplateClipboard_changed(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            uint Session,
            string ClientInfo,
            string Hashes,
            string Archived
            )
        {
            int argumentCount = 9;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Image.Length + 1) * sizeof(char);

                userDataPtr[5].DataPointer = (UInt64)(&Session);
                userDataPtr[5].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(ClientInfo.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(Hashes.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[8].Size = (uint)(Archived.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = Image, a3 = ClientInfo, a4 = Hashes, a5 = Archived)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[6].DataPointer = (ulong)a3;
                    userDataPtr[7].DataPointer = (ulong)a4;
                    userDataPtr[8].DataPointer = (ulong)a5;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateCreateRemoteThread_detected(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid SourceProcessGuid,
            uint SourceProcessId,
            string SourceImage,
            Guid TargetProcessGuid,
            uint TargetProcessId,
            string TargetImage,
            uint NewThreadId,
            string StartAddress,
            string StartModule,
            string StartFunction
            )
        {
            int argumentCount = 12;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&SourceProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&SourceProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(SourceImage.Length + 1) * sizeof(char);

                userDataPtr[5].DataPointer = (UInt64)(&TargetProcessGuid);
                userDataPtr[5].Size = (uint)(sizeof(Guid));

                userDataPtr[6].DataPointer = (UInt64)(&TargetProcessId);
                userDataPtr[6].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(TargetImage.Length + 1) * sizeof(char);

                userDataPtr[8].DataPointer = (UInt64)(&NewThreadId);
                userDataPtr[8].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[9].Size = (uint)(StartAddress.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[10].Size = (uint)(StartModule.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[11].Size = (uint)(StartFunction.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = SourceImage, a3 = TargetImage, a4 = StartAddress, a5 = StartModule, a6 = StartFunction)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[7].DataPointer = (ulong)a3;
                    userDataPtr[9].DataPointer = (ulong)a4;
                    userDataPtr[10].DataPointer = (ulong)a5;
                    userDataPtr[11].DataPointer = (ulong)a6;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateDns_query(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string QueryName,
            string QueryStatus,
            string QueryResults,
            string Image
            )
        {
            int argumentCount = 8;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(QueryName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(QueryStatus.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(QueryResults.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(Image.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = QueryName, a3 = QueryStatus, a4 = QueryResults, a5 = Image)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateDriver_loaded(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            string ImageLoaded,
            string Hashes,
            string Signed,
            string Signature,
            string SignatureStatus
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(ImageLoaded.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[3].Size = (uint)(Hashes.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Signed.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(Signature.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(SignatureStatus.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = ImageLoaded, a3 = Hashes, a4 = Signed, a5 = Signature, a6 = SignatureStatus)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[3].DataPointer = (ulong)a3;
                    userDataPtr[4].DataPointer = (ulong)a4;
                    userDataPtr[5].DataPointer = (ulong)a5;
                    userDataPtr[6].DataPointer = (ulong)a6;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateError_report(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            string ID,
            string Description
            )
        {
            int argumentCount = 3;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(ID.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(Description.Length + 1) * sizeof(char);

                fixed (char* a0 = UtcTime, a1 = ID, a2 = Description)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateFile_Delete(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string User,
            string Image,
            string TargetFilename,
            string Hashes,
            bool IsExecutable,
            string Archived
            )
        {
            int argumentCount = 10;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(User.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(TargetFilename.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(Hashes.Length + 1) * sizeof(char);

                int IsExecutableInt = IsExecutable ? 1 : 0;
                userDataPtr[8].DataPointer = (UInt64)(&IsExecutableInt);
                userDataPtr[8].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[9].Size = (uint)(Archived.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = User, a3 = Image, a4 = TargetFilename, a5 = Hashes, a6 = Archived)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    userDataPtr[9].DataPointer = (ulong)a6;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateFile_created(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetFilename,
            string CreationUtcTime
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(TargetFilename.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(CreationUtcTime.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = Image, a3 = TargetFilename, a4 = CreationUtcTime)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateFile_creation_time_changed(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetFilename,
            string CreationUtcTime,
            string PreviousCreationUtcTime
            )
        {
            int argumentCount = 8;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(TargetFilename.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(CreationUtcTime.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(PreviousCreationUtcTime.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = Image, a3 = TargetFilename, a4 = CreationUtcTime, a5 = PreviousCreationUtcTime)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateFile_stream_created(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetFilename,
            string CreationUtcTime,
            string Hash,
            string Contents
            )
        {
            int argumentCount = 9;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(TargetFilename.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(CreationUtcTime.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(Hash.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[8].Size = (uint)(Contents.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = Image, a3 = TargetFilename, a4 = CreationUtcTime, a5 = Hash, a6 = Contents)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    userDataPtr[8].DataPointer = (ulong)a6;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateImage_loaded(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string ImageLoaded,
            string FileVersion,
            string Description,
            string Product,
            string Company,
            string OriginalFileName,
            string Hashes,
            string Signed,
            string Signature,
            string SignatureStatus
            )
        {
            int argumentCount = 15;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(ImageLoaded.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(FileVersion.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(Description.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[8].Size = (uint)(Product.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[9].Size = (uint)(Company.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[10].Size = (uint)(OriginalFileName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[11].Size = (uint)(Hashes.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[12].Size = (uint)(Signed.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[13].Size = (uint)(Signature.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[14].Size = (uint)(SignatureStatus.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = Image, a3 = ImageLoaded, a4 = FileVersion, a5 = Description, a6 = Product, a7 = Company, a8 = OriginalFileName, a9 = Hashes, a10 = Signed, a11 = Signature, a12 = SignatureStatus)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    userDataPtr[8].DataPointer = (ulong)a6;
                    userDataPtr[9].DataPointer = (ulong)a7;
                    userDataPtr[10].DataPointer = (ulong)a8;
                    userDataPtr[11].DataPointer = (ulong)a9;
                    userDataPtr[12].DataPointer = (ulong)a10;
                    userDataPtr[13].DataPointer = (ulong)a11;
                    userDataPtr[14].DataPointer = (ulong)a12;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateNetwork_connection_detected(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string User,
            string Protocol,
            bool Initiated,
            bool SourceIsIpv6,
            string SourceIp,
            string SourceHostname,
            ushort SourcePort,
            string SourcePortName,
            bool DestinationIsIpv6,
            string DestinationIp,
            string DestinationHostname,
            ushort DestinationPort,
            string DestinationPortName
            )
        {
            int argumentCount = 18;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(User.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(Protocol.Length + 1) * sizeof(char);

                int InitiatedInt = Initiated ? 1 : 0;
                userDataPtr[7].DataPointer = (UInt64)(&InitiatedInt);
                userDataPtr[7].Size = (uint)(sizeof(int));

                int SourceIsIpv6Int = SourceIsIpv6 ? 1 : 0;
                userDataPtr[8].DataPointer = (UInt64)(&SourceIsIpv6Int);
                userDataPtr[8].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[9].Size = (uint)(SourceIp.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[10].Size = (uint)(SourceHostname.Length + 1) * sizeof(char);

                userDataPtr[11].DataPointer = (UInt64)(&SourcePort);
                userDataPtr[11].Size = (uint)(sizeof(short));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[12].Size = (uint)(SourcePortName.Length + 1) * sizeof(char);

                int DestinationIsIpv6Int = DestinationIsIpv6 ? 1 : 0;
                userDataPtr[13].DataPointer = (UInt64)(&DestinationIsIpv6Int);
                userDataPtr[13].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[14].Size = (uint)(DestinationIp.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[15].Size = (uint)(DestinationHostname.Length + 1) * sizeof(char);

                userDataPtr[16].DataPointer = (UInt64)(&DestinationPort);
                userDataPtr[16].Size = (uint)(sizeof(short));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[17].Size = (uint)(DestinationPortName.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = Image, a3 = User, a4 = Protocol, a5 = SourceIp, a6 = SourceHostname, a7 = SourcePortName, a8 = DestinationIp, a9 = DestinationHostname, a10 = DestinationPortName)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[9].DataPointer = (ulong)a5;
                    userDataPtr[10].DataPointer = (ulong)a6;
                    userDataPtr[12].DataPointer = (ulong)a7;
                    userDataPtr[14].DataPointer = (ulong)a8;
                    userDataPtr[15].DataPointer = (ulong)a9;
                    userDataPtr[17].DataPointer = (ulong)a10;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplatePipe_Connected(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string EventType,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string PipeName,
            string Image
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(EventType.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[3].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[3].Size = (uint)(sizeof(Guid));

                userDataPtr[4].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[4].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(PipeName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(Image.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = EventType, a2 = UtcTime, a3 = PipeName, a4 = Image)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplatePipe_Created(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string EventType,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string PipeName,
            string Image
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(EventType.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[3].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[3].Size = (uint)(sizeof(Guid));

                userDataPtr[4].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[4].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(PipeName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(Image.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = EventType, a2 = UtcTime, a3 = PipeName, a4 = Image)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateProcess_Create(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string FileVersion,
            string Description,
            string Product,
            string Company,
            string OriginalFileName,
            string CommandLine,
            string CurrentDirectory,
            string User,
            Guid LogonGuid,
            long LogonId,
            uint TerminalSessionId,
            string IntegrityLevel,
            string Hashes,
            Guid ParentProcessGuid,
            uint ParentProcessId,
            string ParentImage,
            string ParentCommandLine
            )
        {
            int argumentCount = 22;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(FileVersion.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(Description.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(Product.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[8].Size = (uint)(Company.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[9].Size = (uint)(OriginalFileName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[10].Size = (uint)(CommandLine.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[11].Size = (uint)(CurrentDirectory.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[12].Size = (uint)(User.Length + 1) * sizeof(char);

                userDataPtr[13].DataPointer = (UInt64)(&LogonGuid);
                userDataPtr[13].Size = (uint)(sizeof(Guid));

                userDataPtr[14].DataPointer = (UInt64)(&LogonId);
                userDataPtr[14].Size = (uint)(sizeof(long));

                userDataPtr[15].DataPointer = (UInt64)(&TerminalSessionId);
                userDataPtr[15].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[16].Size = (uint)(IntegrityLevel.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[17].Size = (uint)(Hashes.Length + 1) * sizeof(char);

                userDataPtr[18].DataPointer = (UInt64)(&ParentProcessGuid);
                userDataPtr[18].Size = (uint)(sizeof(Guid));

                userDataPtr[19].DataPointer = (UInt64)(&ParentProcessId);
                userDataPtr[19].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[20].Size = (uint)(ParentImage.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[21].Size = (uint)(ParentCommandLine.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = Image, a3 = FileVersion, a4 = Description, a5 = Product, a6 = Company, a7 = OriginalFileName, a8 = CommandLine, a9 = CurrentDirectory, a10 = User, a11 = IntegrityLevel, a12 = Hashes, a13 = ParentImage, a14 = ParentCommandLine)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    userDataPtr[8].DataPointer = (ulong)a6;
                    userDataPtr[9].DataPointer = (ulong)a7;
                    userDataPtr[10].DataPointer = (ulong)a8;
                    userDataPtr[11].DataPointer = (ulong)a9;
                    userDataPtr[12].DataPointer = (ulong)a10;
                    userDataPtr[16].DataPointer = (ulong)a11;
                    userDataPtr[17].DataPointer = (ulong)a12;
                    userDataPtr[20].DataPointer = (ulong)a13;
                    userDataPtr[21].DataPointer = (ulong)a14;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateProcess_accessed(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid SourceProcessGUID,
            uint SourceProcessId,
            uint SourceThreadId,
            string SourceImage,
            Guid TargetProcessGUID,
            uint TargetProcessId,
            string TargetImage,
            int GrantedAccess,
            string CallTrace
            )
        {
            int argumentCount = 11;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&SourceProcessGUID);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&SourceProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                userDataPtr[4].DataPointer = (UInt64)(&SourceThreadId);
                userDataPtr[4].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(SourceImage.Length + 1) * sizeof(char);

                userDataPtr[6].DataPointer = (UInt64)(&TargetProcessGUID);
                userDataPtr[6].Size = (uint)(sizeof(Guid));

                userDataPtr[7].DataPointer = (UInt64)(&TargetProcessId);
                userDataPtr[7].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[8].Size = (uint)(TargetImage.Length + 1) * sizeof(char);

                userDataPtr[9].DataPointer = (UInt64)(&GrantedAccess);
                userDataPtr[9].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[10].Size = (uint)(CallTrace.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = SourceImage, a3 = TargetImage, a4 = CallTrace)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[5].DataPointer = (ulong)a2;
                    userDataPtr[8].DataPointer = (ulong)a3;
                    userDataPtr[10].DataPointer = (ulong)a4;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateProcess_terminated(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image
            )
        {
            int argumentCount = 5;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Image.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = Image)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateRawAccessRead_detected(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string Device
            )
        {
            int argumentCount = 6;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid));

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(Device.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = UtcTime, a2 = Image, a3 = Device)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateRegistry_object_added_or_deleted(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string EventType,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetObject
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(EventType.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[3].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[3].Size = (uint)(sizeof(Guid));

                userDataPtr[4].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[4].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(TargetObject.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = EventType, a2 = UtcTime, a3 = Image, a4 = TargetObject)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateRegistry_object_renamed(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string EventType,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetObject,
            string NewName
            )
        {
            int argumentCount = 8;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(EventType.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[3].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[3].Size = (uint)(sizeof(Guid));

                userDataPtr[4].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[4].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(TargetObject.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(NewName.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = EventType, a2 = UtcTime, a3 = Image, a4 = TargetObject, a5 = NewName)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateRegistry_value_set(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string EventType,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetObject,
            string Details
            )
        {
            int argumentCount = 8;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(EventType.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                userDataPtr[3].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[3].Size = (uint)(sizeof(Guid));

                userDataPtr[4].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[4].Size = (uint)(sizeof(int));

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(Image.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(TargetObject.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(Details.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = EventType, a2 = UtcTime, a3 = Image, a4 = TargetObject, a5 = Details)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateSysmon_config_state_changed(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            string Configuration,
            string ConfigurationFileHash
            )
        {
            int argumentCount = 3;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(Configuration.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(ConfigurationFileHash.Length + 1) * sizeof(char);

                fixed (char* a0 = UtcTime, a1 = Configuration, a2 = ConfigurationFileHash)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateSysmon_service_state_changed(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            string State,
            string Version,
            string SchemaVersion
            )
        {
            int argumentCount = 4;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(State.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(Version.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[3].Size = (uint)(SchemaVersion.Length + 1) * sizeof(char);

                fixed (char* a0 = UtcTime, a1 = State, a2 = Version, a3 = SchemaVersion)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[3].DataPointer = (ulong)a3;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateWmiEventConsumerToFilter_activity_detected(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string EventType,
            string UtcTime,
            string Operation,
            string User,
            string Consumer,
            string Filter
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(EventType.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[3].Size = (uint)(Operation.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(User.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(Consumer.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(Filter.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = EventType, a2 = UtcTime, a3 = Operation, a4 = User, a5 = Consumer, a6 = Filter)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[3].DataPointer = (ulong)a3;
                    userDataPtr[4].DataPointer = (ulong)a4;
                    userDataPtr[5].DataPointer = (ulong)a5;
                    userDataPtr[6].DataPointer = (ulong)a6;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateWmiEventConsumer_activity_detected(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string EventType,
            string UtcTime,
            string Operation,
            string User,
            string Name,
            string Type,
            string Destination
            )
        {
            int argumentCount = 8;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(EventType.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[3].Size = (uint)(Operation.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(User.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(Name.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(Type.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(Destination.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = EventType, a2 = UtcTime, a3 = Operation, a4 = User, a5 = Name, a6 = Type, a7 = Destination)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[3].DataPointer = (ulong)a3;
                    userDataPtr[4].DataPointer = (ulong)a4;
                    userDataPtr[5].DataPointer = (ulong)a5;
                    userDataPtr[6].DataPointer = (ulong)a6;
                    userDataPtr[7].DataPointer = (ulong)a7;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }

        internal unsafe bool TemplateWmiEventFilter_activity_detected(
            ref EventDescriptor eventDescriptor,
            string RuleName,
            string EventType,
            string UtcTime,
            string Operation,
            string User,
            string EventNamespace,
            string Name,
            string Query
            )
        {
            int argumentCount = 8;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[0].Size = (uint)(RuleName.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[1].Size = (uint)(EventType.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[2].Size = (uint)(UtcTime.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[3].Size = (uint)(Operation.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[4].Size = (uint)(User.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[5].Size = (uint)(EventNamespace.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[6].Size = (uint)(Name.Length + 1) * sizeof(char);

                // Value is a nul-terminated string (assume no embedded nuls):
                userDataPtr[7].Size = (uint)(Query.Length + 1) * sizeof(char);

                fixed (char* a0 = RuleName, a1 = EventType, a2 = UtcTime, a3 = Operation, a4 = User, a5 = EventNamespace, a6 = Name, a7 = Query)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[3].DataPointer = (ulong)a3;
                    userDataPtr[4].DataPointer = (ulong)a4;
                    userDataPtr[5].DataPointer = (ulong)a5;
                    userDataPtr[6].DataPointer = (ulong)a6;
                    userDataPtr[7].DataPointer = (ulong)a7;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;
        }
    }
}
