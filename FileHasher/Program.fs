// Learn more about F# at http://fsharp.net
// See the 'F# Tutorial' project for more help.
open System
open System.Diagnostics
open System.IO
open System.Reflection
open System.Text
open System.Security.Cryptography

// Command line parsing module
module CmdParse =
    type SigTypeOption = MD5 | SHA1 | SHA256
    type RecursiveOption = Recursive | NonRecursive

    type CmdLineOptions = {
        sigtype: SigTypeOption list;
        recurs: RecursiveOption
    }

    let printCmdLineHelp() =
        printfn "**************************************"
        printfn "F# FileHasher Command Line Application"
        printfn "**************************************"
        printfn "Command Line Options:"
        printfn "-r: Hash files in subdirectories as well as current directory"
        printfn "-h: Display this information"
        printfn "-a: Hash files using all algorithms"
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
            recurs = NonRecursive
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

            // If the user asks for help, print a command list and stop execution
            | "-h" :: xs | "/h" :: xs ->
                // Including optionsSoFar at the end to satisfy the compiler, even though 'printCmdLineHelp' exits the application
                printCmdLineHelp()
                optionsSoFar

            // Handle any other values by printing to STDERR and continuing
            | x :: xs ->
                eprintfn "Option '%s' is unrecognized" x
                parseCmdLineRec xs optionsSoFar

        // Call the inner recursive function with the default values to get the loop started
        parseCmdLineRec args defaultOptions


// Mess of code
#nowarn40
let hashMsgAgent = MailboxProcessor.Start( fun data ->
    // Message processing function
    let rec messageLoop = async {
        // Read in the data
        let! record, time = data.Receive()

        // Print the received data
//        printfn "\nFilename:\n%s" name
//        printfn "Type: %s" sigType
//        printfn "Signature: %s" hash
//        printfn "Time: %f" time

        return! messageLoop
    }
    messageLoop
)

let time f =
    let timer = new Stopwatch()
    timer.Start()
    let returnValue = f()
    printfn "\nElapsed Time: %f" timer.Elapsed.TotalMilliseconds
    returnValue

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


type HashRecord = {
    md5: string;
    sha1: string;
    sha256: string;
    file: string
}

let md5Hash(input : FileStream) =
    //let timer = new Stopwatch()
    //timer.Start()
    use md5 = MD5.Create()
    let hash = input
                |> md5.ComputeHash
                |> Seq.map ( fun c -> c.ToString("X2") )
                |> Seq.reduce(+)
    //hashMsgAgent.Post (input.Name, hash, "MD5", timer.Elapsed.TotalMilliseconds)
    hash

let sha1Hash(input : FileStream) =
    //let timer = new Stopwatch()
    //timer.Start()
    use sha1 = SHA1.Create()
    let hash = input
                |> sha1.ComputeHash
                |> Seq.map ( fun c -> c.ToString("X2") )
                |> Seq.reduce(+)
    //hashMsgAgent.Post (input.Name, hash, "SHA1", timer.Elapsed.TotalMilliseconds)
    hash

let sha256Hash(input : FileStream) =
    //let timer = new Stopwatch()
    //timer.Start()
    use sha256 = SHA256.Create()
    let hash = input
                |> sha256.ComputeHash
                |> Seq.map ( fun c -> c.ToString("X2") )
                |> Seq.reduce(+)
    //hashMsgAgent.Post (input.Name, hash, "SHA256", timer.Elapsed.TotalMilliseconds)
    hash

let resetStream(stream : FileStream) =
    // Used to reset the FileStream so signatures are consistent. Returns an int that is not needed.
    stream.Seek((int64)0, SeekOrigin.Begin) |> ignore
    stream


// Returns a record of hashes { md5: md5hash; sha1: sha1hash; sha256: sha256hash }
let hashFile (input : FileStream) (options : CmdParse.SigTypeOption list) =
    let drec = {
        md5 = "";
        sha1 = "";
        sha256 = "";
        file = input.Name
    }

    let rec hashFileRec (input : FileStream) options hrecSoFar =
        match options with
        | [] ->
            hrecSoFar

        | CmdParse.MD5 :: xs ->
            let newhrec = { hrecSoFar with md5 = md5Hash input }
            hashFileRec (resetStream input) xs newhrec

        | CmdParse.SHA1 :: xs ->
            let newhrec = { hrecSoFar with sha1 = sha1Hash input }
            hashFileRec (resetStream input) xs newhrec

        | CmdParse.SHA256 :: xs ->
            let newhrec = { hrecSoFar with sha256 = sha256Hash input }
            hashFileRec (resetStream input) xs newhrec

    hashFileRec input options drec


let displayHashResults record time =
    // Add in the time and send it to the mailbox processor
    hashMsgAgent.Post (record, time)



let createFileStream fileName =
    // Using 128Kb buffer size. Note: .NET default is 4Kb buffer size (4096)
    new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true)


let hashDirectory path (options : CmdParse.CmdLineOptions) =
//    try
//        Seq.toArray(getDirectoryDecendants path)
//        |> Array.Parallel.map createFileStream
//        |> match sigType with
//            | "md5" -> Array.Parallel.map md5Hash
//            | "sha1" -> Array.Parallel.map sha1Hash
//            | "sha256" -> Array.Parallel.map sha256Hash
//        |> ignore
//    with
//        | :? ArgumentException -> invalidArg "sigType" (sprintf "%s is not a valid signature type" sigType)
    
    // Get file paths
    let fp = match options.recurs with
                | CmdParse.Recursive ->
                    Seq.toArray (getDirectoryContentsRec path)    

                | CmdParse.NonRecursive ->
                    Seq.toArray (getDirectoryContents path)

    fp 
    |> Array.Parallel.map createFileStream
    |> Array.Parallel.map ( fun x -> hashFile x options.sigtype )
    |> ignore



[<EntryPoint>]
let main argv = 

    // Parse the user's command line options
    let argvList = Array.toList argv
    let options = CmdParse.parseCmdLine argvList
    //printfn "%A" options

    // Get the path of the the directory that the program is run in
    let path = Environment.CurrentDirectory
    //printfn "%s" path




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
//        | "md5" -> time( fun() -> hashDirectory path "md5" )
//                   //hashDirectory path "md5"
//                   None
//        | "sha1" -> time( fun() -> hashDirectory path "sha1" )
//                    None
//        | "sha256" -> time( fun() -> hashDirectory path "sha256" )
//                      None
//        | _ -> None
//
//    Seq.pick run readlines |> ignore
    0 // return an integer exit code