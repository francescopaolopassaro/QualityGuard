Imports System.Diagnostics
Imports System.Security.Cryptography

Module Vulnerable
    Sub Run(input As String)
        Process.Start(input)
        Dim md5 = MD5.Create()
        Dim r = New Random()
        Dim password = "hunter2"
    End Sub
End Module