$Source = @" 

using System; 

namespace Sunny 
{ 
    public static class Greeting  
    { 
        public static void Hello() 
        { 
            
            Console.WriteLine("Hello"); 
        } 

        public static void Add(int a, int b) 
        { 
            
            Console.WriteLine(a+b); 
        } 
         
        
    } 
} 
"@ 

Add-Type -TypeDefinition $Source -Language CSharp  

[Sunny.Greeting]::Add(5,6)
