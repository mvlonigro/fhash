using System;
using System.IO;

using FHash;

namespace fhash_app
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Working...");

            var path = Environment.CurrentDirectory;

            Console.WriteLine("Directory hashes: ");

            var fhash = new FHashDirectory(path, true);
            var hashes = fhash.HashDirectory(SignatureType.MD5);
            foreach (var hash in hashes)
            {
                Console.WriteLine("File path: " + hash.Key);
                Console.WriteLine("Signature: " + hash.Value);
            }

            Console.WriteLine("File hashes: ");
            var di = new DirectoryInfo(path);
            var files = di.GetFiles();

            var fhash2 = new FHashFile(files[0].FullName);
            var fileHash = fhash2.HashFile(SignatureType.MD5);
            Console.WriteLine("File path: " + fileHash.Key);
            Console.WriteLine("Signature: " + fileHash.Value);
            fileHash = fhash2.HashFile(SignatureType.MD5);
            Console.WriteLine("File path attempt 2: " + fileHash.Key);
            Console.WriteLine("Signature attempt 2: " + fileHash.Value);

#if DEBUG
            Console.WriteLine("Press enter to close...");
            Console.ReadLine();
#endif
        }
    }
}
