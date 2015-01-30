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
    let time f =
        let timer = new Stopwatch()
        timer.Start()
        let returnValue = f()
        printfn "\nElapsed Time: %f" timer.Elapsed.TotalMilliseconds
        returnValue

    let convertBytesToHex (bytes:byte[]) =
        bytes
        |> Seq.map( fun c -> c.ToString("X2") )
        |> Seq.reduce(+)

    let convertHexStrToBytes (hexstr:string) =
        hexstr
        |> Seq.windowed 2
        |> Seq.mapi( fun i j -> (i,j) )
        |> Seq.filter( fun (i,j) -> i % 2 = 0 )
        |> Seq.map( fun (_,j) -> Byte.Parse(new String(j), Globalization.NumberStyles.AllowHexSpecifier) )
        |> Seq.toArray

    // Turns an internal F# record into a KeyValuePair with key: file name and value: requested signature
    let convertToKeyValuePair (hRecord : DomainTypes.HashRecord) =
        new KeyValuePair<string, string>(hRecord.file, hRecord.signature)


module internal FileReader =
    open CommonLibrary
    open DomainTypes

    let rec getDirectoryContentsRec path =
        seq {
            // Get all files in this directory. yield! merges sequence of files into parent sequence
            yield! Directory.GetFiles path
            // For each directory in this directory, recursively run getDirectoryDecendants
            for p in Directory.GetDirectories path do
            yield! getDirectoryContentsRec p
        }

    let getDirectoryContents path =
        seq {
            yield! Directory.GetFiles path
        }

    let getFilesInPath path recOption =
        match recOption with
        | true ->
            getDirectoryContentsRec path
        | false ->
            getDirectoryContents path

    let resetStream(stream : FileStream) =
        // Used to reset the FileStream so signatures are consistent. Returns an int that is not needed.
        stream.Seek((int64)0, SeekOrigin.Begin) |> ignore
        stream

    let createFileStream fileName =
        // Using 128Kb buffer size. Note: .NET default is 4Kb buffer size (4096)
        new FileStream (fileName, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true)

// Note: Using an enum instead of union for non F# .NET compatibility
/// Signature algorithm types that work with FHash 
type SignatureType = MD5=0 | SHA1=1 | SHA256=2

module internal FileHasher = 
    open CommonLibrary
    open DomainTypes
    // Private Functions
    let md5Hash (input : FileStream) =
        use md5 = MD5.Create()
        input
        |> md5.ComputeHash
        |> convertBytesToHex

    let sha1Hash (input : FileStream) =
        use sha1 = SHA1.Create()
        input
        |> sha1.ComputeHash
        |> convertBytesToHex

    let sha256Hash (input : FileStream) =
        use sha256 = SHA256.Create()
        input
        |> sha256.ComputeHash
        |> convertBytesToHex

    let hashFile fileInput sigType =
        match sigType with
        | SignatureType.MD5 ->
            md5Hash fileInput
        | SignatureType.SHA1 ->
            sha1Hash fileInput
        | SignatureType.SHA256 ->
            sha256Hash fileInput

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
