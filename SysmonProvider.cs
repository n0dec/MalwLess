/*
 * Author: 	@n0dec
 * License: GNU General Public License v3.0
 * 
 */

namespace Sysmon.Namespace
{
using System;
using System.Diagnostics.Eventing;
using System.Runtime.InteropServices;

    public static class SYSMON_PROVIDER
    {
        //
        // Provider Microsoft-Windows-Sysmon Event Count 22
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


        static SYSMON_PROVIDER()
        {
            unchecked
            {
                SYSMON_ERROR_EVENT = new EventDescriptor(0xff, 0x3, 0x10, 0x2, 0x0, 0xff, (long)0x8000000000000000);
                SYSMON_CREATE_PROCESS_EVENT = new EventDescriptor(0x1, 0x5, 0x10, 0x4, 0x0, 0x1, (long)0x8000000000000000);
                SYSMON_FILE_TIME_EVENT = new EventDescriptor(0x2, 0x4, 0x10, 0x4, 0x0, 0x2, (long)0x8000000000000000);
                SYSMON_NETWORK_CONNECT_EVENT = new EventDescriptor(0x3, 0x5, 0x10, 0x4, 0x0, 0x3, (long)0x8000000000000000);
                SYSMON_SERVICE_STATE_CHANGE_EVENT = new EventDescriptor(0x4, 0x3, 0x10, 0x4, 0x0, 0x4, (long)0x8000000000000000);
                SYSMON_PROCESS_TERMINATE_EVENT = new EventDescriptor(0x5, 0x3, 0x10, 0x4, 0x0, 0x5, (long)0x8000000000000000);
                SYSMON_DRIVER_LOAD_EVENT = new EventDescriptor(0x6, 0x3, 0x10, 0x4, 0x0, 0x6, (long)0x8000000000000000);
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
        public static bool EventWriteSYSMON_CREATE_PROCESS_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string FileVersion, string Description, string Product, string Company, string CommandLine, string CurrentDirectory, string User, Guid LogonGuid, long LogonId, uint TerminalSessionId, string IntegrityLevel, string Hashes, Guid ParentProcessGuid, uint ParentProcessId, string ParentImage, string ParentCommandLine)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateProcess_Create(ref SYSMON_CREATE_PROCESS_EVENT, UtcTime, ProcessGuid, ProcessId, Image, FileVersion, Description, Product, Company, CommandLine, CurrentDirectory, User, LogonGuid, LogonId, TerminalSessionId, IntegrityLevel, Hashes, ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine);
        }

        //
        // Event method for SYSMON_FILE_TIME_EVENT
        //
        public static bool EventWriteSYSMON_FILE_TIME_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetFilename, string CreationUtcTime, string PreviousCreationUtcTime)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateFile_creation_time_changed(ref SYSMON_FILE_TIME_EVENT, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime);
        }

        //
        // Event method for SYSMON_NETWORK_CONNECT_EVENT
        //
        public static bool EventWriteSYSMON_NETWORK_CONNECT_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string User, string Protocol, bool Initiated, bool SourceIsIpv6, string SourceIp, string SourceHostname, ushort SourcePort, string SourcePortName, bool DestinationIsIpv6, string DestinationIp, string DestinationHostname, ushort DestinationPort, string DestinationPortName)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateNetwork_connection_detected(ref SYSMON_NETWORK_CONNECT_EVENT, UtcTime, ProcessGuid, ProcessId, Image, User, Protocol, Initiated, SourceIsIpv6, SourceIp, SourceHostname, SourcePort, SourcePortName, DestinationIsIpv6, DestinationIp, DestinationHostname, DestinationPort, DestinationPortName);
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
        public static bool EventWriteSYSMON_PROCESS_TERMINATE_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string Image)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateProcess_terminated(ref SYSMON_PROCESS_TERMINATE_EVENT, UtcTime, ProcessGuid, ProcessId, Image);
        }

        //
        // Event method for SYSMON_DRIVER_LOAD_EVENT
        //
        public static bool EventWriteSYSMON_DRIVER_LOAD_EVENT(string UtcTime, string ImageLoaded, string Hashes, string Signed, string Signature, string SignatureStatus)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateDriver_loaded(ref SYSMON_DRIVER_LOAD_EVENT, UtcTime, ImageLoaded, Hashes, Signed, Signature, SignatureStatus);
        }

        //
        // Event method for SYSMON_IMAGE_LOAD_EVENT
        //
        public static bool EventWriteSYSMON_IMAGE_LOAD_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string ImageLoaded, string FileVersion, string Description, string Product, string Company, string Hashes, string Signed, string Signature, string SignatureStatus)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateImage_loaded(ref SYSMON_IMAGE_LOAD_EVENT, UtcTime, ProcessGuid, ProcessId, Image, ImageLoaded, FileVersion, Description, Product, Company, Hashes, Signed, Signature, SignatureStatus);
        }

        //
        // Event method for SYSMON_CREATE_REMOTE_THREAD_EVENT
        //
        public static bool EventWriteSYSMON_CREATE_REMOTE_THREAD_EVENT(string UtcTime, Guid SourceProcessGuid, uint SourceProcessId, string SourceImage, Guid TargetProcessGuid, uint TargetProcessId, string TargetImage, uint NewThreadId, string StartAddress, string StartModule, string StartFunction)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateCreateRemoteThread_detected(ref SYSMON_CREATE_REMOTE_THREAD_EVENT, UtcTime, SourceProcessGuid, SourceProcessId, SourceImage, TargetProcessGuid, TargetProcessId, TargetImage, NewThreadId, StartAddress, StartModule, StartFunction);
        }

        //
        // Event method for SYSMON_RAWACCESS_READ_EVENT
        //
        public static bool EventWriteSYSMON_RAWACCESS_READ_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string Device)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateRawAccessRead_detected(ref SYSMON_RAWACCESS_READ_EVENT, UtcTime, ProcessGuid, ProcessId, Image, Device);
        }

        //
        // Event method for SYSMON_ACCESS_PROCESS_EVENT
        //
        public static bool EventWriteSYSMON_ACCESS_PROCESS_EVENT(string UtcTime, Guid SourceProcessGUID, uint SourceProcessId, uint SourceThreadId, string SourceImage, Guid TargetProcessGUID, uint TargetProcessId, string TargetImage, int GrantedAccess, string CallTrace)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateProcess_accessed(ref SYSMON_ACCESS_PROCESS_EVENT, UtcTime, SourceProcessGUID, SourceProcessId, SourceThreadId, SourceImage, TargetProcessGUID, TargetProcessId, TargetImage, GrantedAccess, CallTrace);
        }

        //
        // Event method for SYSMON_FILE_CREATE_EVENT
        //
        public static bool EventWriteSYSMON_FILE_CREATE_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetFilename, string CreationUtcTime)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateFile_created(ref SYSMON_FILE_CREATE_EVENT, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime);
        }

        //
        // Event method for SYSMON_REG_KEY_EVENT
        //
        public static bool EventWriteSYSMON_REG_KEY_EVENT(string EventType, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetObject)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateRegistry_object_added_or_deleted(ref SYSMON_REG_KEY_EVENT, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject);
        }

        //
        // Event method for SYSMON_REG_SETVALUE_EVENT
        //
        public static bool EventWriteSYSMON_REG_SETVALUE_EVENT(string EventType, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetObject, string Details)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateRegistry_value_set(ref SYSMON_REG_SETVALUE_EVENT, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject, Details);
        }

        //
        // Event method for SYSMON_REG_NAME_EVENT
        //
        public static bool EventWriteSYSMON_REG_NAME_EVENT(string EventType, string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetObject, string NewName)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateRegistry_object_renamed(ref SYSMON_REG_NAME_EVENT, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject, NewName);
        }

        //
        // Event method for SYSMON_FILE_CREATE_STREAM_HASH_EVENT
        //
        public static bool EventWriteSYSMON_FILE_CREATE_STREAM_HASH_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string Image, string TargetFilename, string CreationUtcTime, string Hash)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateFile_stream_created(ref SYSMON_FILE_CREATE_STREAM_HASH_EVENT, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime, Hash);
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
        public static bool EventWriteSYSMON_CREATE_NAMEDPIPE_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string PipeName, string Image)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplatePipe_Created(ref SYSMON_CREATE_NAMEDPIPE_EVENT, UtcTime, ProcessGuid, ProcessId, PipeName, Image);
        }

        //
        // Event method for SYSMON_CONNECT_NAMEDPIPE_EVENT
        //
        public static bool EventWriteSYSMON_CONNECT_NAMEDPIPE_EVENT(string UtcTime, Guid ProcessGuid, uint ProcessId, string PipeName, string Image)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplatePipe_Connected(ref SYSMON_CONNECT_NAMEDPIPE_EVENT, UtcTime, ProcessGuid, ProcessId, PipeName, Image);
        }

        //
        // Event method for SYSMON_WMI_FILTER_EVENT
        //
        public static bool EventWriteSYSMON_WMI_FILTER_EVENT(string EventType, string UtcTime, string Operation, string User, string EventNamespace, string Name, string Query)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateWmiEventFilter_activity_detected(ref SYSMON_WMI_FILTER_EVENT, EventType, UtcTime, Operation, User, EventNamespace, Name, Query);
        }

        //
        // Event method for SYSMON_WMI_CONSUMER_EVENT
        //
        public static bool EventWriteSYSMON_WMI_CONSUMER_EVENT(string EventType, string UtcTime, string Operation, string User, string Name, string Type, string Destination)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateWmiEventConsumer_activity_detected(ref SYSMON_WMI_CONSUMER_EVENT, EventType, UtcTime, Operation, User, Name, Type, Destination);
        }

        //
        // Event method for SYSMON_WMI_BINDING_EVENT
        //
        public static bool EventWriteSYSMON_WMI_BINDING_EVENT(string EventType, string UtcTime, string Operation, string User, string Consumer, string Filter)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateWmiEventConsumerToFilter_activity_detected(ref SYSMON_WMI_BINDING_EVENT, EventType, UtcTime, Operation, User, Consumer, Filter);
        }
    }

    internal class EventProviderVersionTwo : EventProvider
    {
         internal EventProviderVersionTwo(Guid id)
                : base(id)
         {}


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

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(ID.Length + 1)*sizeof(char);

                userDataPtr[2].Size = (uint)(Description.Length + 1)*sizeof(char);

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



        internal unsafe bool TemplateProcess_Create(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string FileVersion,
            string Description,
            string Product,
            string Company,
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
            int argumentCount = 20;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(FileVersion.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(Description.Length + 1)*sizeof(char);

                userDataPtr[6].Size = (uint)(Product.Length + 1)*sizeof(char);

                userDataPtr[7].Size = (uint)(Company.Length + 1)*sizeof(char);

                userDataPtr[8].Size = (uint)(CommandLine.Length + 1)*sizeof(char);

                userDataPtr[9].Size = (uint)(CurrentDirectory.Length + 1)*sizeof(char);

                userDataPtr[10].Size = (uint)(User.Length + 1)*sizeof(char);

                userDataPtr[11].DataPointer = (UInt64)(&LogonGuid);
                userDataPtr[11].Size = (uint)(sizeof(Guid)  );

                userDataPtr[12].DataPointer = (UInt64)(&LogonId);
                userDataPtr[12].Size = (uint)(sizeof(long)  );

                userDataPtr[13].DataPointer = (UInt64)(&TerminalSessionId);
                userDataPtr[13].Size = (uint)(sizeof(int)  );

                userDataPtr[14].Size = (uint)(IntegrityLevel.Length + 1)*sizeof(char);

                userDataPtr[15].Size = (uint)(Hashes.Length + 1)*sizeof(char);

                userDataPtr[16].DataPointer = (UInt64)(&ParentProcessGuid);
                userDataPtr[16].Size = (uint)(sizeof(Guid)  );

                userDataPtr[17].DataPointer = (UInt64)(&ParentProcessId);
                userDataPtr[17].Size = (uint)(sizeof(int)  );

                userDataPtr[18].Size = (uint)(ParentImage.Length + 1)*sizeof(char);

                userDataPtr[19].Size = (uint)(ParentCommandLine.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = Image, a2 = FileVersion, a3 = Description, a4 = Product, a5 = Company, a6 = CommandLine, a7 = CurrentDirectory, a8 = User, a9 = IntegrityLevel, a10 = Hashes, a11 = ParentImage, a12 = ParentCommandLine)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    userDataPtr[8].DataPointer = (ulong)a6;
                    userDataPtr[9].DataPointer = (ulong)a7;
                    userDataPtr[10].DataPointer = (ulong)a8;
                    userDataPtr[14].DataPointer = (ulong)a9;
                    userDataPtr[15].DataPointer = (ulong)a10;
                    userDataPtr[18].DataPointer = (ulong)a11;
                    userDataPtr[19].DataPointer = (ulong)a12;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateFile_creation_time_changed(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetFilename,
            string CreationUtcTime,
            string PreviousCreationUtcTime
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(TargetFilename.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(CreationUtcTime.Length + 1)*sizeof(char);

                userDataPtr[6].Size = (uint)(PreviousCreationUtcTime.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = Image, a2 = TargetFilename, a3 = CreationUtcTime, a4 = PreviousCreationUtcTime)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateNetwork_connection_detected(
            ref EventDescriptor eventDescriptor,
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
            int argumentCount = 17;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(User.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(Protocol.Length + 1)*sizeof(char);

                int InitiatedInt = Initiated ? 1 : 0;
                userDataPtr[6].DataPointer = (UInt64)(&InitiatedInt);
                userDataPtr[6].Size = (uint)(sizeof(int));

                int SourceIsIpv6Int = SourceIsIpv6 ? 1 : 0;
                userDataPtr[7].DataPointer = (UInt64)(&SourceIsIpv6Int);
                userDataPtr[7].Size = (uint)(sizeof(int));

                userDataPtr[8].Size = (uint)(SourceIp.Length + 1)*sizeof(char);

                userDataPtr[9].Size = (uint)(SourceHostname.Length + 1)*sizeof(char);

                userDataPtr[10].DataPointer = (UInt64)(&SourcePort);
                userDataPtr[10].Size = (uint)(sizeof(short)  );

                userDataPtr[11].Size = (uint)(SourcePortName.Length + 1)*sizeof(char);

                int DestinationIsIpv6Int = DestinationIsIpv6 ? 1 : 0;
                userDataPtr[12].DataPointer = (UInt64)(&DestinationIsIpv6Int);
                userDataPtr[12].Size = (uint)(sizeof(int));

                userDataPtr[13].Size = (uint)(DestinationIp.Length + 1)*sizeof(char);

                userDataPtr[14].Size = (uint)(DestinationHostname.Length + 1)*sizeof(char);

                userDataPtr[15].DataPointer = (UInt64)(&DestinationPort);
                userDataPtr[15].Size = (uint)(sizeof(short)  );

                userDataPtr[16].Size = (uint)(DestinationPortName.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = Image, a2 = User, a3 = Protocol, a4 = SourceIp, a5 = SourceHostname, a6 = SourcePortName, a7 = DestinationIp, a8 = DestinationHostname, a9 = DestinationPortName)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[8].DataPointer = (ulong)a4;
                    userDataPtr[9].DataPointer = (ulong)a5;
                    userDataPtr[11].DataPointer = (ulong)a6;
                    userDataPtr[13].DataPointer = (ulong)a7;
                    userDataPtr[14].DataPointer = (ulong)a8;
                    userDataPtr[16].DataPointer = (ulong)a9;
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

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(State.Length + 1)*sizeof(char);

                userDataPtr[2].Size = (uint)(Version.Length + 1)*sizeof(char);

                userDataPtr[3].Size = (uint)(SchemaVersion.Length + 1)*sizeof(char);

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



        internal unsafe bool TemplateProcess_terminated(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image
            )
        {
            int argumentCount = 4;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(Image.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = Image)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateDriver_loaded(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            string ImageLoaded,
            string Hashes,
            string Signed,
            string Signature,
            string SignatureStatus
            )
        {
            int argumentCount = 6;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(ImageLoaded.Length + 1)*sizeof(char);

                userDataPtr[2].Size = (uint)(Hashes.Length + 1)*sizeof(char);

                userDataPtr[3].Size = (uint)(Signed.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(Signature.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(SignatureStatus.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = ImageLoaded, a2 = Hashes, a3 = Signed, a4 = Signature, a5 = SignatureStatus)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[3].DataPointer = (ulong)a3;
                    userDataPtr[4].DataPointer = (ulong)a4;
                    userDataPtr[5].DataPointer = (ulong)a5;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateImage_loaded(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string ImageLoaded,
            string FileVersion,
            string Description,
            string Product,
            string Company,
            string Hashes,
            string Signed,
            string Signature,
            string SignatureStatus
            )
        {
            int argumentCount = 13;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(ImageLoaded.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(FileVersion.Length + 1)*sizeof(char);

                userDataPtr[6].Size = (uint)(Description.Length + 1)*sizeof(char);

                userDataPtr[7].Size = (uint)(Product.Length + 1)*sizeof(char);

                userDataPtr[8].Size = (uint)(Company.Length + 1)*sizeof(char);

                userDataPtr[9].Size = (uint)(Hashes.Length + 1)*sizeof(char);

                userDataPtr[10].Size = (uint)(Signed.Length + 1)*sizeof(char);

                userDataPtr[11].Size = (uint)(Signature.Length + 1)*sizeof(char);

                userDataPtr[12].Size = (uint)(SignatureStatus.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = Image, a2 = ImageLoaded, a3 = FileVersion, a4 = Description, a5 = Product, a6 = Company, a7 = Hashes, a8 = Signed, a9 = Signature, a10 = SignatureStatus)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
                    userDataPtr[7].DataPointer = (ulong)a5;
                    userDataPtr[8].DataPointer = (ulong)a6;
                    userDataPtr[9].DataPointer = (ulong)a7;
                    userDataPtr[10].DataPointer = (ulong)a8;
                    userDataPtr[11].DataPointer = (ulong)a9;
                    userDataPtr[12].DataPointer = (ulong)a10;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateCreateRemoteThread_detected(
            ref EventDescriptor eventDescriptor,
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
            int argumentCount = 11;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&SourceProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&SourceProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(SourceImage.Length + 1)*sizeof(char);

                userDataPtr[4].DataPointer = (UInt64)(&TargetProcessGuid);
                userDataPtr[4].Size = (uint)(sizeof(Guid)  );

                userDataPtr[5].DataPointer = (UInt64)(&TargetProcessId);
                userDataPtr[5].Size = (uint)(sizeof(int)  );

                userDataPtr[6].Size = (uint)(TargetImage.Length + 1)*sizeof(char);

                userDataPtr[7].DataPointer = (UInt64)(&NewThreadId);
                userDataPtr[7].Size = (uint)(sizeof(int)  );

                userDataPtr[8].Size = (uint)(StartAddress.Length + 1)*sizeof(char);

                userDataPtr[9].Size = (uint)(StartModule.Length + 1)*sizeof(char);

                userDataPtr[10].Size = (uint)(StartFunction.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = SourceImage, a2 = TargetImage, a3 = StartAddress, a4 = StartModule, a5 = StartFunction)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[6].DataPointer = (ulong)a2;
                    userDataPtr[8].DataPointer = (ulong)a3;
                    userDataPtr[9].DataPointer = (ulong)a4;
                    userDataPtr[10].DataPointer = (ulong)a5;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateRawAccessRead_detected(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string Device
            )
        {
            int argumentCount = 5;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(Device.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = Image, a2 = Device)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateProcess_accessed(
            ref EventDescriptor eventDescriptor,
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
            int argumentCount = 10;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&SourceProcessGUID);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&SourceProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].DataPointer = (UInt64)(&SourceThreadId);
                userDataPtr[3].Size = (uint)(sizeof(int)  );

                userDataPtr[4].Size = (uint)(SourceImage.Length + 1)*sizeof(char);

                userDataPtr[5].DataPointer = (UInt64)(&TargetProcessGUID);
                userDataPtr[5].Size = (uint)(sizeof(Guid)  );

                userDataPtr[6].DataPointer = (UInt64)(&TargetProcessId);
                userDataPtr[6].Size = (uint)(sizeof(int)  );

                userDataPtr[7].Size = (uint)(TargetImage.Length + 1)*sizeof(char);

                userDataPtr[8].DataPointer = (UInt64)(&GrantedAccess);
                userDataPtr[8].Size = (uint)(sizeof(int)  );

                userDataPtr[9].Size = (uint)(CallTrace.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = SourceImage, a2 = TargetImage, a3 = CallTrace)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[4].DataPointer = (ulong)a1;
                    userDataPtr[7].DataPointer = (ulong)a2;
                    userDataPtr[9].DataPointer = (ulong)a3;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateFile_created(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetFilename,
            string CreationUtcTime
            )
        {
            int argumentCount = 6;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(TargetFilename.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(CreationUtcTime.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = Image, a2 = TargetFilename, a3 = CreationUtcTime)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateRegistry_object_added_or_deleted(
            ref EventDescriptor eventDescriptor,
            string EventType,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetObject
            )
        {
            int argumentCount = 6;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(EventType.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid)  );

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int)  );

                userDataPtr[4].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(TargetObject.Length + 1)*sizeof(char);

                fixed (char* a0 = EventType, a1 = UtcTime, a2 = Image, a3 = TargetObject)
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



        internal unsafe bool TemplateRegistry_value_set(
            ref EventDescriptor eventDescriptor,
            string EventType,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetObject,
            string Details
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(EventType.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid)  );

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int)  );

                userDataPtr[4].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(TargetObject.Length + 1)*sizeof(char);

                userDataPtr[6].Size = (uint)(Details.Length + 1)*sizeof(char);

                fixed (char* a0 = EventType, a1 = UtcTime, a2 = Image, a3 = TargetObject, a4 = Details)
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



        internal unsafe bool TemplateRegistry_object_renamed(
            ref EventDescriptor eventDescriptor,
            string EventType,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetObject,
            string NewName
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(EventType.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[2].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[2].Size = (uint)(sizeof(Guid)  );

                userDataPtr[3].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[3].Size = (uint)(sizeof(int)  );

                userDataPtr[4].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(TargetObject.Length + 1)*sizeof(char);

                userDataPtr[6].Size = (uint)(NewName.Length + 1)*sizeof(char);

                fixed (char* a0 = EventType, a1 = UtcTime, a2 = Image, a3 = TargetObject, a4 = NewName)
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



        internal unsafe bool TemplateFile_stream_created(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string Image,
            string TargetFilename,
            string CreationUtcTime,
            string Hash
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(Image.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(TargetFilename.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(CreationUtcTime.Length + 1)*sizeof(char);

                userDataPtr[6].Size = (uint)(Hash.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = Image, a2 = TargetFilename, a3 = CreationUtcTime, a4 = Hash)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    userDataPtr[5].DataPointer = (ulong)a3;
                    userDataPtr[6].DataPointer = (ulong)a4;
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

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(Configuration.Length + 1)*sizeof(char);

                userDataPtr[2].Size = (uint)(ConfigurationFileHash.Length + 1)*sizeof(char);

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



        internal unsafe bool TemplatePipe_Created(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string PipeName,
            string Image
            )
        {
            int argumentCount = 5;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(PipeName.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(Image.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = PipeName, a2 = Image)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplatePipe_Connected(
            ref EventDescriptor eventDescriptor,
            string UtcTime,
            Guid ProcessGuid,
            uint ProcessId,
            string PipeName,
            string Image
            )
        {
            int argumentCount = 5;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ProcessGuid);
                userDataPtr[1].Size = (uint)(sizeof(Guid)  );

                userDataPtr[2].DataPointer = (UInt64)(&ProcessId);
                userDataPtr[2].Size = (uint)(sizeof(int)  );

                userDataPtr[3].Size = (uint)(PipeName.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(Image.Length + 1)*sizeof(char);

                fixed (char* a0 = UtcTime, a1 = PipeName, a2 = Image)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateWmiEventFilter_activity_detected(
            ref EventDescriptor eventDescriptor,
            string EventType,
            string UtcTime,
            string Operation,
            string User,
            string EventNamespace,
            string Name,
            string Query
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(EventType.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[2].Size = (uint)(Operation.Length + 1)*sizeof(char);

                userDataPtr[3].Size = (uint)(User.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(EventNamespace.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(Name.Length + 1)*sizeof(char);

                userDataPtr[6].Size = (uint)(Query.Length + 1)*sizeof(char);

                fixed (char* a0 = EventType, a1 = UtcTime, a2 = Operation, a3 = User, a4 = EventNamespace, a5 = Name, a6 = Query)
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
            string EventType,
            string UtcTime,
            string Operation,
            string User,
            string Name,
            string Type,
            string Destination
            )
        {
            int argumentCount = 7;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(EventType.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[2].Size = (uint)(Operation.Length + 1)*sizeof(char);

                userDataPtr[3].Size = (uint)(User.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(Name.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(Type.Length + 1)*sizeof(char);

                userDataPtr[6].Size = (uint)(Destination.Length + 1)*sizeof(char);

                fixed (char* a0 = EventType, a1 = UtcTime, a2 = Operation, a3 = User, a4 = Name, a5 = Type, a6 = Destination)
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



        internal unsafe bool TemplateWmiEventConsumerToFilter_activity_detected(
            ref EventDescriptor eventDescriptor,
            string EventType,
            string UtcTime,
            string Operation,
            string User,
            string Consumer,
            string Filter
            )
        {
            int argumentCount = 6;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(EventType.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(UtcTime.Length + 1)*sizeof(char);

                userDataPtr[2].Size = (uint)(Operation.Length + 1)*sizeof(char);

                userDataPtr[3].Size = (uint)(User.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(Consumer.Length + 1)*sizeof(char);

                userDataPtr[5].Size = (uint)(Filter.Length + 1)*sizeof(char);

                fixed (char* a0 = EventType, a1 = UtcTime, a2 = Operation, a3 = User, a4 = Consumer, a5 = Filter)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    userDataPtr[3].DataPointer = (ulong)a3;
                    userDataPtr[4].DataPointer = (ulong)a4;
                    userDataPtr[5].DataPointer = (ulong)a5;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }

    }

}
