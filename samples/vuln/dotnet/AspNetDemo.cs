using System;
using System.Net.Http;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

public class OrdersController : Controller
{
    private readonly ILogger _log;

    [HttpPost]
    [IgnoreAntiforgeryToken]
    public IActionResult Transfer(string name)
    {
        var input = Request.Query["file"];
        var bytes = File.ReadAllBytes(Path.Combine("/data", input));
        context.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'");
        Response.Cookies.Append("session", name);
        _log.LogInformation("password is {0}", name);
        var client = new HttpClient();
        if (Regex.IsMatch(input, "(a+)+$")) { }
        if (orders.Count() > 0) { }
        var now = DateTime.Now;
        return Redirect(input);
    }

    public async void SaveAsync() { await repository.SaveAsync(); }

    public void Load()
    {
        try { Work(); }
        catch (Exception ex) { throw ex; }
        try { Work(); }
        catch { }
    }

    public static string Cache = "x";
}
