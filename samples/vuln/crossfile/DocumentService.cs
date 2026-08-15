using System.IO;

public class DocumentService
{
    private readonly RequestReader _reader = new();

    public string Load()
    {
        var path = ReadRequestedFile();
        return File.ReadAllText(path);
    }
}
