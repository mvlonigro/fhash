// Learn more about F# at http://fsharp.net
// See the 'F# Tutorial' project for more help.
open System
open System.Diagnostics
open System.IO
open System.Reflection
open System.Text
open System.Security.Cryptography


//=======================
// Common Library
//=======================
module CommonLibrary =
    let time f =
        let timer = new Stopwatch()
        timer.Start()
        let returnValue = f()
        printfn "\nElapsed Time: %f" timer.Elapsed.TotalMilliseconds
        returnValue

    let convertBytesToHex (bytes:byte[]) =
        bytes
        |> Seq.map ( fun c -> c.ToString("X2") )
        |> Seq.reduce(+)

    let convertHexStrToBytes (hexstr:string) =
        hexstr
        |> Seq.windowed 2
        |> Seq.mapi ( fun i j -> (i,j) )
        |> Seq.filter ( fun (i,j) -> i % 2 = 0 )
        |> Seq.map ( fun (_,j) -> Byte.Parse(new String(j), Globalization.NumberStyles.AllowHexSpecifier) )
        |> Seq.toArray

//=======================
// Command line parsing
//=======================
module CmdParse =
    type SigTypeOption = MD5 | SHA1 | SHA256
    type RecursiveOption = Recursive | NonRecursive
    type TimeOption = Time | NoTime
    type RunModeOption = RunModeDefault | RunMode1 | RunMode2 | RunMode3
    type SeedOption = WithSeed | WithoutSeed

    type CmdLineOptions = {
        sigtype: SigTypeOption list;
        recurs: RecursiveOption;
        time: TimeOption;
        mode: RunModeOption;
        seedop: SeedOption;
        seed: string
    }

    let printCmdLineHelp() =
        printfn "======================================"
        printfn "F# FileHasher Command Line Application"
        printfn "======================================"
        printfn "Command Line Options:"
        printfn "-r: Hash files in subdirectories as well as current directory"
        printfn "-t: Display times"
        printfn "-a: Hash files using all algorithms"
        printfn "-h: Display this information"
        printfn ""
        printfn "Signature Type Options (can declare any or all or none)"
        printfn "-md5: Hash files using the MD5 algorithm"
        printfn "-sha1: Hash files using the SHA1 algorithm"
        printfn "-sha256: Hash files usin the SHA256 algorithm"
        Environment.Exit 0

    let parseCmdLine args =
        // Start with default arguments
        let defaultOptions = {
            sigtype = [MD5];
            recurs = NonRecursive;
            time = NoTime;
            mode = RunModeDefault;
            seedop = WithoutSeed;
            seed = null
        }

        // Inner function is the recursive function used to loop over the array of arguments
        let rec parseCmdLineRec args optionsSoFar =
            match args with
            // Empty list is the end condition, so return the list of arguments
            | [] -> 
                optionsSoFar

            // Match on the recursion flag - allows hashing of subdirectories
            | "-r" :: xs | "/r" :: xs -> 
                let newOptionsSoFar = { optionsSoFar with recurs = Recursive }
                parseCmdLineRec xs newOptionsSoFar

            | "-t" :: xs | "/t" :: xs ->
                let newOptionsSoFar = { optionsSoFar with time = Time }
                parseCmdLineRec xs newOptionsSoFar

            // Add MD5 to the list of signature types (duplicates in the list won't matter - we're only checking if it exists)
            | "-md5" :: xs | "/md5" :: xs ->
                let newOptionsSoFar = { optionsSoFar with sigtype = MD5 :: optionsSoFar.sigtype }
                parseCmdLineRec xs newOptionsSoFar

            // Add SHA1 to the list of signature types
            | "-sha1" :: xs | "/sha1" :: xs ->
                let newOptionsSoFar = { optionsSoFar with sigtype = SHA1 :: optionsSoFar.sigtype }
                parseCmdLineRec xs newOptionsSoFar

            // Add SHA256 to the list of signature types
            | "-sha256" :: xs | "/sha256" :: xs ->
                let newOptionsSoFar = { optionsSoFar with sigtype = SHA256 :: optionsSoFar.sigtype }
                parseCmdLineRec xs newOptionsSoFar

            | "-a" :: xs | "/a" :: xs ->
                let newOptionsSoFar = { optionsSoFar with sigtype = [MD5; SHA1; SHA256] }
                parseCmdLineRec xs newOptionsSoFar

            | "-s" :: xs | "/s" :: xs ->
                // Take the next item as the seed, then continue the loop with the next, next item
                match xs with
                | x :: xss ->
                    let newOptionsSoFar = { optionsSoFar with seedop = WithSeed; seed = x }
                    parseCmdLineRec xss newOptionsSoFar
                | [] ->
                    eprintfn "A seed must be provided if using the -s option."
                    // Exit the program
                    Environment.Exit(1)
                    optionsSoFar //<-- added just to satisfy the compiler, program should exit before this

            | "-1" :: xs | "/1" :: xs ->
                let newOptionsSoFar = { optionsSoFar with mode = RunMode1 }
                parseCmdLineRec xs newOptionsSoFar

            | "-2" :: xs | "/2" :: xs ->
                let newOptionsSoFar = { optionsSoFar with mode = RunMode2 }
                parseCmdLineRec xs newOptionsSoFar

            | "-3" :: xs | "/3" :: xs ->
                let newOptionsSoFar = { optionsSoFar with mode = RunMode3 }
                parseCmdLineRec xs newOptionsSoFar

            // If the user asks for help, print a command list and stop execution
            | "-h" :: xs | "/h" :: xs ->
                // Including optionsSoFar at the end to satisfy the compiler, even though 'printCmdLineHelp' exits the application
                printCmdLineHelp()
                optionsSoFar //<-- added just to satisfy the compiler, program should exit before this

            // Handle any other values by printing to STDERR and continuing
            | x :: xs ->
                eprintfn "Option '%s' is unrecognized" x
                parseCmdLineRec xs optionsSoFar

        // Call the inner recursive function with the default values to get the loop started
        parseCmdLineRec args defaultOptions

//========================
// Domain Types
//========================
 module DomainTypes =
    type HashRecord = {
        md5: string;
        md5time: float;
        sha1: string;
        sha1time: float;
        sha256: string;
        sha256time: float;
        file: string;
        size: string;
    }

//==========================
// Console Display
//==========================
#nowarn40
module ConsoleDisplay =
    open DomainTypes
    
    let hashMsgAgent = MailboxProcessor.Start( fun data ->
        // Message processing function
        let rec messageLoop = async {
            // Read in the data
            let! (record, timeop) = data.Receive()

            // Print the received data
            printfn "\nFile name: %s" record.file
            printfn "File size: %s" record.size
            match record.md5 with
            | null ->
                None |> ignore
            | _ -> 
                printfn "MD5: %s" record.md5

            match (timeop, record.md5time) with
            | (CmdParse.NoTime, _) ->
                None |> ignore
            | (CmdParse.Time, 0.0) ->
                None |> ignore
            | (CmdParse.Time, _) ->
                printfn "MD5 Time Elapsed: %f" record.md5time

            match record.sha1 with
            | null ->
                None |> ignore
            | _ -> 
                printfn "SHA1: %s" record.sha1

            match (timeop, record.sha1time) with
            | (CmdParse.NoTime, _) ->
                None |> ignore
            | (CmdParse.Time, 0.0) ->
                None |> ignore
            | (CmdParse.Time, _) ->
                printfn "SHA1 Time Elapsed: %f" record.sha1time

            match record.sha256 with
            | null ->
                None |> ignore
            | _ -> 
                printfn "SHA256: %s" record.sha256

            match (timeop, record.sha256time) with
            | (CmdParse.NoTime, _) ->
                None |> ignore
            | (CmdParse.Time, 0.0) ->
                None |> ignore
            | (CmdParse.Time, _) ->
                printfn "SHA256 Time Elapsed: %f" record.sha256time


            return! messageLoop
        }
        messageLoop
    )

    let hashMsg record timeop = 
        // Print the received data
        printfn "\nFile name: %s" record.file
        printfn "File size: %s" record.size
        match record.md5 with
        | null ->
            None |> ignore
        | _ -> 
            printfn "MD5: %s" record.md5

        match (timeop, record.md5time) with
        | (CmdParse.NoTime, _) ->
            None |> ignore
        | (CmdParse.Time, 0.0) ->
            None |> ignore
        | (CmdParse.Time, _) ->
            printfn "MD5 Time Elapsed: %f" record.md5time

        match record.sha1 with
        | null ->
            None |> ignore
        | _ -> 
            printfn "SHA1: %s" record.sha1

        match (timeop, record.sha1time) with
        | (CmdParse.NoTime, _) ->
            None |> ignore
        | (CmdParse.Time, 0.0) ->
            None |> ignore
        | (CmdParse.Time, _) ->
            printfn "SHA1 Time Elapsed: %f" record.sha1time

        match record.sha256 with
        | null ->
            None |> ignore
        | _ -> 
            printfn "SHA256: %s" record.sha256

        match (timeop, record.sha256time) with
        | (CmdParse.NoTime, _) ->
            None |> ignore
        | (CmdParse.Time, 0.0) ->
            None |> ignore
        | (CmdParse.Time, _) ->
            printfn "SHA256 Time Elapsed: %f" record.sha256time



//================================
// File Reader
//================================
module FileReader =
    open CommonLibrary
    open CmdParse

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
        | Recursive ->
            getDirectoryContentsRec path
        | NonRecursive ->
            getDirectoryContents path

    let resetStream(stream : FileStream) =
        // Used to reset the FileStream so signatures are consistent. Returns an int that is not needed.
        stream.Seek((int64)0, SeekOrigin.Begin) |> ignore
        stream

    let createFileStream fileName options =
        match options.seedop with
        | WithoutSeed ->
            // Using 128Kb buffer size. Note: .NET default is 4Kb buffer size (4096)
            new FileStream (fileName, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true)

        | WithSeed ->
            // Open file
            let fs = new FileStream (fileName, FileMode.Append, FileAccess.Write, FileShare.Read, 131072, true)
            let bytes = convertHexStrToBytes options.seed
            // Append seed bytes
            fs.Write( bytes, 0, bytes.Length )
            resetStream fs

//=========================
// Hasher
//=========================
module Hasher =
    open CommonLibrary
    open DomainTypes
    open FileReader
    open ConsoleDisplay
    open CmdParse

    let md5Hash (input : FileStream) =
        use md5 = MD5.Create()
        let hash = input
                    |> md5.ComputeHash
                    |> convertBytesToHex
        hash

    let sha1Hash (input : FileStream) =
        use sha1 = SHA1.Create()
        let hash = input
                    |> sha1.ComputeHash
                    |> convertBytesToHex
        hash

    let sha256Hash (input : FileStream) =
        use sha256 = SHA256.Create()
        let hash = input
                    |> sha256.ComputeHash
                    |> convertBytesToHex
        hash

    // Returns a record of hashes { md5: md5hash; sha1: sha1hash; sha256: sha256hash }
    let hashFile (input : FileStream) (options : CmdLineOptions) =
        let filesize = input.Length
        let drec = {
            md5 = null;
            md5time = 0.0;
            sha1 = null;
            sha1time = 0.0;
            sha256 = null;
            sha256time = 0.0;
            file = input.Name;
            size = (filesize / (int64)1000).ToString() + " KB (" + filesize.ToString() + " bytes)" ;
        }

        let rec hashFileRec (input : FileStream) options hrecSoFar =
            match options.sigtype with
            | [] ->
                hrecSoFar

            | CmdParse.MD5 :: xs ->
                let timer = new Stopwatch()
                timer.Start()
                let newhrec = { hrecSoFar with md5 = md5Hash input; md5time = timer.Elapsed.TotalMilliseconds }
                hashFileRec (resetStream input) { options with sigtype = xs } newhrec

            | CmdParse.SHA1 :: xs ->
                let timer = new Stopwatch()
                timer.Start()
                let newhrec = { hrecSoFar with sha1 = sha1Hash input; sha1time = timer.Elapsed.TotalMilliseconds }
                hashFileRec (resetStream input) { options with sigtype = xs } newhrec

            | CmdParse.SHA256 :: xs ->
                let timer = new Stopwatch()
                timer.Start()
                let newhrec = { hrecSoFar with sha256 = sha256Hash input; sha256time = timer.Elapsed.TotalMilliseconds }
                hashFileRec (resetStream input) { options with sigtype = xs } newhrec

        hashFileRec input options drec

    // Default option
    //  Parallel read, Parallel hash, Sequential display
    let hashDirectory path (options : CmdParse.CmdLineOptions) =
        let fp = Seq.toArray (getFilesInPath path options.recurs)
        fp 
        |> Array.Parallel.map ( fun x -> createFileStream x options )
        |> Array.Parallel.map ( fun x -> hashFile x options )
        //|> Array.Parallel.map ( fun x -> hashMsgAgent.Post (x, options.time) ) //parallel
        |> Array.map ( fun x -> hashMsg x options.time )

    // Alternate option 1
    //  Sequential file read, Parallel hash, Sequential display
    let hashDirectory1 path (options : CmdLineOptions) =
        Seq.toArray (getFilesInPath path options.recurs)
        |> Array.map ( fun x -> createFileStream x options )
        |> Array.Parallel.map ( fun x -> hashFile x options )
        |> Array.map ( fun x -> hashMsg x options.time )

    // Alternate option 2
    //  Parallel file read, Sequential hash, Sequential display
    let hashDirectory2 path (options : CmdLineOptions) =
        Seq.toArray (getFilesInPath path options.recurs)
        |> Array.Parallel.map ( fun x -> createFileStream x options )
        |> Array.map ( fun x -> hashFile x options )
        |> Array.map ( fun x -> hashMsg x options.time )

    // Alternate option 2
    //  Sequential file read, Sequential hash, Sequential display
    let hashDirectory3 path (options : CmdLineOptions) =
        Seq.toArray (getFilesInPath path options.recurs)
        |> Array.map ( fun x -> createFileStream x options )
        |> Array.map ( fun x -> hashFile x options )
        |> Array.map ( fun x -> hashMsg x options.time )

module Main =
    open CmdParse
    open Hasher

    [<EntryPoint>]
    let main argv = 
        let timer = new Stopwatch()
        timer.Start()
        // Parse the user's command line options
        let argvList = Array.toList argv
        let options = parseCmdLine argvList

        printfn "Working..."
        // Get the path of the the directory that the program is run in
        let path = Environment.CurrentDirectory


        // Main event function
        match options.mode with
        | RunModeDefault -> 
            hashDirectory path options |> ignore
        | RunMode1 ->
            printfn "Running Demo Mode 1: Sequential File Read, Parallel File Hash"
            hashDirectory1 path options |> ignore
        | RunMode2 ->
            printfn "Running Demo Mode 2: Parallel File Read, Sequential File Hash"
            hashDirectory2 path options |> ignore
        | RunMode3 ->
            printfn "Running Demo Mode 3: Sequential File Read, Sequential File Hash"
            hashDirectory3 path options |> ignore

        // Console 'loop'
    //    printfn "Press 'q' to exit"
    //
    //    let action = fun _ ->
    //        Console.Write "\nEnter Input: "
    //        Console.ReadLine()
    //
    //    let readlines = Seq.initInfinite( fun _ -> action() )
    //
    //    let run item = 
    //        match item with
    //        | "q" -> Some item
    //        | _ -> None
    //
    //    Seq.pick run readlines |> ignore

        // Print the total program execution time
        printfn "\nTotal Execution Time: %f" timer.Elapsed.TotalMilliseconds
    
        0 // return an integer exit code