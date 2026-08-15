using Microsoft.AspNetCore.Mvc;

public class RequestReader
{
    public string ReadRequestedFile()
    {
        return Request.Query["file"];
    }
}
