// Learn more about F# at http://fsharp.net
// See the 'F# Tutorial' project for more help.

open System
open System.Diagnostics
open System.IO
open System.Reflection
open System.Text
open System.Security.Cryptography

#nowarn40
let hashMsgAgent = MailboxProcessor.Start( fun data ->
    // Message processing function
    let rec messageLoop = async {
        // Read in the data
        let! name, hash, sigType, time = data.Receive()

        // Print the received data
        printfn "\nFilename:\n%s" name
        printfn "Type: %s" sigType
        printfn "Signature: %s" hash
        printfn "Time: %f" time

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

let rec getDirectoryDecendants path =
    seq {
        // Get all files in this directory. yield! merges sequence of files into parent sequence
        yield! Directory.GetFiles(path)
        // For each directory in this directory, recursively run getDirectoryDecendants
        for p in Directory.GetDirectories(path) do
        yield! getDirectoryDecendants p
    }

let md5Hash(input : FileStream) =
    let timer = new Stopwatch()
    timer.Start()
    use md5 = MD5.Create()
    let hash = input
                |> md5.ComputeHash
                |> Seq.map ( fun c -> c.ToString("X2") )
                |> Seq.reduce(+)
    hashMsgAgent.Post (input.Name, hash, "MD5", timer.Elapsed.TotalMilliseconds)
    hash

let sha1Hash(input : FileStream) =
    let timer = new Stopwatch()
    timer.Start()
    use sha1 = SHA1.Create()
    let hash = input
                |> sha1.ComputeHash
                |> Seq.map ( fun c -> c.ToString("X2") )
                |> Seq.reduce(+)
    hashMsgAgent.Post (input.Name, hash, "SHA1", timer.Elapsed.TotalMilliseconds)
    hash

let sha256Hash(input : FileStream) =
    let timer = new Stopwatch()
    timer.Start()
    use sha256 = SHA256.Create()
    let hash = input
                |> sha256.ComputeHash
                |> Seq.map ( fun c -> c.ToString("X2") )
                |> Seq.reduce(+)
    hashMsgAgent.Post (input.Name, hash, "SHA256", timer.Elapsed.TotalMilliseconds)
    hash

let resetStream(stream : FileStream) =
    stream.Seek((int64)0, SeekOrigin.Begin)

let createFileStream fileName =
    // Using 128Kb buffer size. Note: .NET default is 4Kb buffer size (4096)
    new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, true)


let hashDirectory path sigType =
    try
        Seq.toArray(getDirectoryDecendants path)
        |> Array.Parallel.map createFileStream
        |> match sigType with
            | "md5" -> Array.Parallel.map md5Hash
            | "sha1" -> Array.Parallel.map sha1Hash
            | "sha256" -> Array.Parallel.map sha256Hash
        |> ignore
    with
        | :? ArgumentException -> invalidArg "sigType" (sprintf "%s is not a valid signature type" sigType)



[<EntryPoint>]
let main argv = 

    let path = Environment.CurrentDirectory

    // Console 'loop'
    printfn "Press 'q' to exit"

    let action = fun _ ->
        Console.Write "\nEnter Input: "
        Console.ReadLine()

    let readlines = Seq.initInfinite( fun _ -> action() )

    let run item = 
        match item with
        | "q" -> Some item
        | "md5" -> time( fun() -> hashDirectory path "md5" )
                   //hashDirectory path "md5"
                   None
        | "sha1" -> time( fun() -> hashDirectory path "sha1" )
                    None
        | "sha256" -> time( fun() -> hashDirectory path "sha256" )
                      None
        | _ -> None

    Seq.pick run readlines |> ignore
    0 // return an integer exit code