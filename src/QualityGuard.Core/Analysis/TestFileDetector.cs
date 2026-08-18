namespace QualityGuard.Core.Analysis;

/// <summary>
/// Decides whether a file belongs to a test suite, so that coverage on the tests themselves does not
/// dilute the number the gate holds production code to. Naming conventions differ by language and
/// framework, so this recognises the common ones on the path and the file name; anything that is not
/// clearly a test file is production code.
/// </summary>
public static class TestFileDetector
{
    private static readonly HashSet<string> TestDirectoryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "__tests__", "__specs__", "test", "tests", "spec", "specs", "testing", "e2e", "uitests"
    };

    public static bool IsTestFile(string path)
    {
        var segments = path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
            return false;

        var fileName = segments[^1];

        // a directory named "tests" makes every file inside it a test, whatever its own name is
        for (var i = 0; i < segments.Length - 1; i++)
        {
            if (TestDirectoryNames.Contains(segments[i]))
                return true;
        }

        // library tests live next to the production code, so the file name tells the story; the
        // camel case matches Java, Kotlin and C# conventions, while the underscores match Python and Go
        var baseName = fileName.Contains('.') ? fileName[..fileName.LastIndexOf('.')] : fileName;
        if (baseName.StartsWith("test_", StringComparison.OrdinalIgnoreCase))
            return true;
        if (baseName.EndsWith("_test", StringComparison.OrdinalIgnoreCase))
            return true;
        if (baseName.EndsWith("Test", StringComparison.Ordinal))
            return true;
        if (baseName.EndsWith("Tests", StringComparison.Ordinal))
            return true;
        if (baseName.EndsWith("Spec", StringComparison.Ordinal))
            return true;
        if (fileName.Contains(".test.", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains(".spec.", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
}