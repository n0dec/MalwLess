/*
 * Author:  @n0dec
 * License: GNU General Public License v3.0
 * 
 */

namespace PowerShell.Namespace
{
using System;
using System.Diagnostics.Eventing;
using System.Runtime.InteropServices;

    public static class MicrosoftWindowsPowerShell_PROVIDER
    {
        //
        // Provider Microsoft-Windows-PowerShell Event Count 2
        //

        internal static EventProviderVersionTwo m_provider = new EventProviderVersionTwo(new Guid("a0c1853b-5c40-4b15-8766-3cf1c58f985a"));
        //
        // Task :  eventGUIDs
        //

        //
        // Event Descriptors
        //
        private static EventDescriptor EventID_4103;
        private static EventDescriptor EventID_4104;


        static MicrosoftWindowsPowerShell_PROVIDER()
        {
            unchecked
            {
                EventID_4103 = new EventDescriptor(0x1007, 0x1, 0x10, 0x4, 0x14, 0x6A, (long)0x0);
                EventID_4104 = new EventDescriptor(0x1008, 0x1, 0x10, 0x3, 0xf, 0x2, (long)0x0);
            }
        }


        //
        // Event method for EventID_4103
        //
        public static bool EventWriteEventID_4103(string ContextInfo, string UserData, string Payload)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateEventID_4103_Template(ref EventID_4103, ContextInfo, UserData, Payload);
        }

        //
        // Event method for EventID_4104
        //
        public static bool EventWriteEventID_4104(int MessageNumber, int MessageTotal, string ScriptBlockText, string ScriptBlockId, string Path)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateEventID_4104_Template(ref EventID_4104, MessageNumber, MessageTotal, ScriptBlockText, ScriptBlockId, Path);
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



        internal unsafe bool TemplateEventID_4103_Template(
            ref EventDescriptor eventDescriptor,
            string ContextInfo,
            string UserData,
            string Payload
            )
        {
            int argumentCount = 3;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(ContextInfo.Length + 1)*sizeof(char);

                userDataPtr[1].Size = (uint)(UserData.Length + 1)*sizeof(char);

                userDataPtr[2].Size = (uint)(Payload.Length + 1)*sizeof(char);

                fixed (char* a0 = ContextInfo, a1 = UserData, a2 = Payload)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    userDataPtr[1].DataPointer = (ulong)a1;
                    userDataPtr[2].DataPointer = (ulong)a2;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateEventID_4104_Template(
            ref EventDescriptor eventDescriptor,
            int MessageNumber,
            int MessageTotal,
            string ScriptBlockText,
            string ScriptBlockId,
            string Path
            )
        {
            int argumentCount = 5;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].DataPointer = (UInt64)(&MessageNumber);
                userDataPtr[0].Size = (uint)(sizeof(int)  );

                userDataPtr[1].DataPointer = (UInt64)(&MessageTotal);
                userDataPtr[1].Size = (uint)(sizeof(int)  );

                userDataPtr[2].Size = (uint)(ScriptBlockText.Length + 1)*sizeof(char);

                userDataPtr[3].Size = (uint)(ScriptBlockId.Length + 1)*sizeof(char);

                userDataPtr[4].Size = (uint)(Path.Length + 1)*sizeof(char);

                fixed (char* a0 = ScriptBlockText, a1 = ScriptBlockId, a2 = Path)
                {
                    userDataPtr[2].DataPointer = (ulong)a0;
                    userDataPtr[3].DataPointer = (ulong)a1;
                    userDataPtr[4].DataPointer = (ulong)a2;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }

    }

}
