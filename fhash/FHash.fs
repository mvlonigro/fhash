namespace FHash

open System
open System.Diagnostics
open System.Collections
open System.Collections.Generic
open System.IO
open System.Reflection
open System.Text
open System.Security.Cryptography


//==========================
// Private internal modules
//==========================

/// Internal types used by library
 module internal DomainTypes =
    /// Main type used to store file hashes
    type HashRecord = {
        signature: string;
        file: string;
        size: string;
    }

/// Some utility functions used in this library
module internal CommonLibrary =
    /// Times the execution of a function and prints it to stdout
    let time f =
        let timer = new Stopwatch()
        timer.Start()
        let returnValue = f()
        printfn "\nElapsed Time: %f" timer.Elapsed.TotalMilliseconds
        returnValue

    /// Converts a byte array into a string representation of a hex value
    let convertBytesToHex (bytes:byte[]) =
        bytes
        |> Seq.map( fun c -> c.ToString("X2") )
        |> Seq.reduce(+)

    /// Converts a string representation of a hex value into a byte array
    let convertHexStrToBytes (hexstr:string) =
        hexstr
        |> Seq.windowed 2
        |> Seq.mapi( fun i j -> (i,j) )
        |> Seq.filter( fun (i,j) -> i % 2 = 0 )
        |> Seq.map( fun (_,j) -> Byte.Parse(new String(j), Globalization.NumberStyles.AllowHexSpecifier) )
        |> Seq.toArray

    /// Turns an internal F# record into a KeyValuePair with key: file name and value: requested signature
    let convertToKeyValuePair (hRecord : DomainTypes.HashRecord) =
        new KeyValuePair<string, string>(hRecord.file, hRecord.signature)

/// Functions relating to reading files
module internal FileReader =
    open CommonLibrary
    open DomainTypes

    /// Gets all file paths in the provided directory path + all subdirectory paths
    let rec getDirectoryContentsRec path =
        seq {
            // Get all files in this directory. yield! merges sequence of files into parent sequence
            yield! Directory.GetFiles path
            // For each directory in this directory, recursively run getDirectoryDecendants
            for p in Directory.GetDirectories path do
            yield! getDirectoryContentsRec p
        }

    /// Gets all file paths in the provided directory path
    let getDirectoryContents path =
        seq {
            yield! Directory.GetFiles path
        }

    /// Decides whether to use recursive or non-recursive directory contents function
    let getFilesInPath path recOption =
        match recOption with
        | true ->
            getDirectoryContentsRec path
        | false ->
            getDirectoryContents path

    /// Resets the FileStream so signatures are consistent. Returns an int that is not needed.
    let resetStream(stream : FileStream) =
        stream.Seek((int64)0, SeekOrigin.Begin) |> ignore
        stream

    /// Creates a .NET filestream object from a file path (with some default values)
    let createFileStream fileName =
        // Using 128Kb buffer size. Note: .NET default is 4Kb buffer size (4096)
        new FileStream (fileName, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true)

// Note: Using an enum instead of union for non F# .NET compatibility
/// Signature algorithm types that work with FHash 
type SignatureType = MD5=0 | SHA1=1 | SHA256=2

/// Functions related to file hashing
module internal FileHasher = 
    open CommonLibrary
    open DomainTypes
    
    /// Create an MD5 signature of a filestream
    let md5Hash (input : FileStream) =
        use md5 = MD5.Create()
        input
        |> md5.ComputeHash
        |> convertBytesToHex

    /// Create a SHA1 signature of a filestream
    let sha1Hash (input : FileStream) =
        use sha1 = SHA1.Create()
        input
        |> sha1.ComputeHash
        |> convertBytesToHex

    /// Create a SHA256 signature of a filestream
    let sha256Hash (input : FileStream) =
        use sha256 = SHA256.Create()
        input
        |> sha256.ComputeHash
        |> convertBytesToHex

    /// Choose which hashing algorithm to use
    let hashFile fileInput sigType =
        match sigType with
        | SignatureType.MD5 ->
            md5Hash fileInput
        | SignatureType.SHA1 ->
            sha1Hash fileInput
        | SignatureType.SHA256 ->
            sha256Hash fileInput

    /// Creates a HashRecord from a file stream
    let populateHashRecord fileInput sigType =
        {
            signature = hashFile fileInput sigType;
            file = fileInput.Name;
            size = fileInput.Length.ToString();
        }

//=========================
// Publicly exposed class
//=========================
/// The FHash .NET class for hashing a directory of files
type FHashDirectory(path, recurs) =
    // Gets all the file paths based on the root path
    let filePaths = FileReader.getFilesInPath path recurs |> Seq.toArray

    member this.HashDirectory sigType =
        filePaths
        // Create file streams out of the file paths in parallel
        |> Array.Parallel.map FileReader.createFileStream
        // Get the signature for each file stream in parallel
        |> Array.Parallel.map ( fun x -> FileHasher.populateHashRecord x sigType )
        // Stick the results into an easily accessible .NET collection (Array of key-value pairs)
        |> Array.Parallel.map CommonLibrary.convertToKeyValuePair

/// The FHash .NET class for hashing a single file
type FHashFile(path) =
    let fileStream = FileReader.createFileStream path
    member this.fileStream
        with private get() =
            FileReader.resetStream fileStream

    member this.HashFile sigType =
        FileHasher.populateHashRecord this.fileStream sigType
        |> CommonLibrary.convertToKeyValuePair
