using System.Diagnostics;
using System.Security.Cryptography;
using System.Data.SqlClient;

class Vulnerable
{
    void Run(string input)
    {
        Process.Start(input);
        using var md5 = MD5.Create();
        using var cmd = new SqlCommand("SELECT * FROM t WHERE id = " + input);
        var r = new Random();
        string password = "hunter2";
    }
}