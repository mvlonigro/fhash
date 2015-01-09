FHash
==========

A Windows command line program designed to hash all files in the directory that it is run. Can hash files using MD5, SHA1,
and SHA256 algorithms. This program takes advantage of F#'s Array.Parallel to hash files concurrently for a more than 2x
speedup.

How To Use
-----------

Download the files in this repo, then open FileHasher.sln in Visual Studio 2012 or later. Build the program in Visual Studio,
then run the FileHasher.exe that is created. Run the file in the directory of the files to be hashed.

Use FileHasher.exe [-h] to see a list of available command line arguments.

A more descriptive README is coming soon!
