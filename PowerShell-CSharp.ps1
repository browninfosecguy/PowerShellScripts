$source = @"
using System;
class Program
    {
        public static void Main()
        {
            Console.WriteLine("Hello");
            Console.ReadLine();
        }
     }
"@

Add-Type -TypeDefinition $source -Language CSharp -OutputAssembly "cat.exe" -OutputType ConsoleApplication