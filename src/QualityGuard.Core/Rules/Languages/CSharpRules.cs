using QualityGuard.Core.Models;
using QualityGuard.Core.Syntax;
using QualityGuard.Core.Tokenization;

namespace QualityGuard.Core.Rules.Languages;

public static class CSharpRuleSet
{
    public static IReadOnlyList<IRule> All { get; } =
    [
        new CsEmptyCommentRule(),
        new CsPathTraversalRule(),
        new CsUploadedFileNameRule(),
        new CsMutableCollectionPropertyRule(),
        new CsProcessExecutionRule(),
        new CsSqlInjectionRule(),
        new CsWeakCryptoRule(),
        new CsHardcodedCredentialsRule(),
        new CsWeakRandomRule(),
        new CsDynamicTypeResolutionRule(),
        new CsXmlParsingRule(),
        new CsAssemblyLoadRule(),
        new CsCleartextHttpRule(),
        new CsInsecureCookieRule(),
        new CsUnsafeDeserializationRule(),
        new CsSwitchDefaultRule(),
        new CsGotoRule(),
        new CsGcCollectRule(),
        new CsUnsafeBlockRule(),
        new CsDateTimeNowRule(),
        new CsAsyncVoidRule(),
        new CsSsrRule(),
        new CsLdapInjectionRule(),
        new CsHeaderInjectionRule(),
        new CsCorsWildcardRule(),
        new CsXmlDeserializationRule(),
        new CsHardcodedConnectionStringRule(),
        new CsInsecurePasswordValidationRule(),
        new CsWeakKeySizeRule(),
        new CsInsecureJwtRule(),
        new CsDisabledCertValidationRule(),
        new CsEntityFrameworkSqlInjectionRule(),
        new CsOpenRedirectRule(),
        new CsExceptionInfoLeakRule(),
        new CsInsecureTempFileRule(),
        new CsStringConcatInLoopRule(),
        new CsImplicitToStringRule(),
        new CsAsyncWithoutAwaitRule(),
        new CsCountInsteadOfAnyRule(),
        new CsDivisionByZeroRule(),
        new CsMissingDisposalRule(),
        new CsDeadStoreRule(),
        new CsNullReferenceRule(),
        new CsFloatEqualityRule(),
        new CsCollectionModifiedRule(),
        new CsTaskBlockingRule(),
        new CsOffByOneLoopRule(),
        new CsPascalCaseMethodRule(),
        new CsCamelCaseLocalRule(),
        new CsInterfacePrefixRule(),
        new CsConstNamingRule()
    ];

    internal static string[] LinesOf(IRuleContext context) => context.File.Content.Split('\n');

    internal static string LineAt(IRuleContext context, int line)
    {
        var lines = LinesOf(context);
        return line >= 1 && line <= lines.Length ? lines[line - 1] : "";
    }

    internal static bool IsWord(Token token, string name, bool caseInsensitive = false)
        => (token.Kind is TokenKind.Identifier or TokenKind.Keyword) &&
           (caseInsensitive
               ? string.Equals(token.Text, name, StringComparison.OrdinalIgnoreCase)
               : token.Text == name);

    internal static bool IsWord(Token token, string[] names, bool caseInsensitive = false)
        => (token.Kind is TokenKind.Identifier or TokenKind.Keyword)
           && RuleMatchers.Contains(token.Text, names, caseInsensitive);

    internal static bool IsWord(string text, string[] names, bool caseInsensitive = false)
        => RuleMatchers.Contains(text, names, caseInsensitive);

    internal static bool HasAny(string text, string[] fragments)
        => fragments.Any(f => text.Contains(f, StringComparison.OrdinalIgnoreCase));

    internal static bool IsCredentialName(Token token)
    {
        if (token.Kind is not (TokenKind.Identifier or TokenKind.Keyword)) return false;
        return IsWord(token.Text, ["password", "pass", "pwd", "secret", "token", "apikey", "credential"], true);
    }

    internal static bool IsMemberAccess(IReadOnlyList<Token> tokens, int index, string baseName, string member)
        => index >= 2
           && IsWord(tokens[index - 2], baseName)
           && tokens[index - 1].Text == "."
           && IsWord(tokens[index], member);

    internal static bool NextArgIsConstant(IReadOnlyList<Token> tokens, int index)
    {
        for (var j = index + 1; j < tokens.Count; j++)
        {
            if (tokens[j].Text == "(")
                continue;
            if (tokens[j].Text is ";" or "," or "=" or "{" or ")" or "]")
                return false;
            return tokens[j].Kind == TokenKind.String && !tokens[j].Text.Contains('{');
        }
        return false;
    }

    internal static bool IsEmptyCatch(IReadOnlyList<Token> tokens, int index)
    {
        var k = index + 1;
        if (k < tokens.Count && tokens[k].Text == "(")
        {
            var depth = 0;
            for (; k < tokens.Count; k++)
            {
                if (tokens[k].Text == "(") depth++;
                else if (tokens[k].Text == ")")
                {
                    depth--;
                    if (depth == 0) { k++; break; }
                }
            }
        }
        while (k < tokens.Count && tokens[k].Text != "{" && tokens[k].Text != ";")
            k++;
        return k + 1 < tokens.Count && tokens[k].Text == "{" && tokens[k + 1].Text == "}";
    }
}

public sealed class CsProcessExecutionRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0001";
    public override string Name => "Execution of externally-influenced OS commands";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Validate and allow list the process file name and arguments.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i + 1].Text != "(") continue;
            if (CSharpRuleSet.IsMemberAccess(tokens, i, "Process", "Start")
                && !RuleMatchers.NextNonParenIsString(tokens, i)
                // flow-aware: flag only when external input reaches this line, or when the file
                // carries no taint evidence at all (single-file scan of a vulnerable sample)
                && (context.Taint == null
                    || context.IsTaintedLine(tokens[i].Line)))
                context.Report("Sanitize arguments passed to Process.Start.", tokens[i].Line);
            if (CSharpRuleSet.IsWord(tokens[i], "ProcessStartInfo")
                && !RuleMatchers.NextNonParenIsString(tokens, i)
                && (context.Taint == null || context.IsTaintedLine(tokens[i].Line)))
                context.Report("Validate the file name used to build the process.", tokens[i].Line);
        }
    }
}

public sealed class CsSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0002";
    public override string Name => "SQL injection via concatenated queries";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use parameterized queries to prevent SQL injection.";
    public override string[] Languages => ["cs", "vb"];

    private static readonly string[] SqlSinkMethods =
    [
        "CommandText",
        // command types: any provider-specific *Command/*DataAdapter/connection is a SQL sink
        "SqlCommand", "OdbcCommand", "OracleCommand", "SqlCeCommand", "MySqlCommand",
        "SqliteCommand", "SQLiteCommand", "NpgsqlCommand", "OleDbCommand", "SqlCommand2",
        "SqlDataAdapter", "OdbcDataAdapter", "OracleDataAdapter", "SqlCeDataAdapter",
        "MySqlDataAdapter", "SQLiteDataAdapter", "NpgsqlDataAdapter", "OleDbDataAdapter",
        // EF / Dapper entry points
        "FromSqlRaw", "FromSql", "ExecuteQuery", "ExecuteUpdate", "Query",
        "ExecuteNonQuery", "ExecuteScalar", "ExecuteReader",
        // MySqlHelper.ExecuteDataRow(connection, query): the query is the second argument
        "ExecuteDataRow"
    ];

    public override void Execute(IRuleContext context)
    {
        // Add framework sinks from cs-aspnet.yaml
        var fwSinks = context.Frameworks.GetSinks("cs")
            .Where(s => s.Kind == "sql")
            .Select(s => s.Method)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var allSinks = SqlSinkMethods.Concat(fwSinks).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Identifier)
                continue;
            var sink = allSinks.FirstOrDefault(s => string.Equals(tokens[i].Text, s, StringComparison.OrdinalIgnoreCase));
            if (sink == null)
                continue;

            // 'Query' is only a sink as an invocation (connection.Query(...)). As a plain variable
            // named `query` it would turn every `query &= literal` into dynamic SQL.
            if (string.Equals(sink, "Query", StringComparison.OrdinalIgnoreCase)
                && !IsInvocation(tokens, i))
                continue;

            var line = tokens[i].Line;

            // The SQL statement argument, restricted to where the statement actually lives. A
            // `*DataAdapter(query, connection)` has the statement in arg 1 and a connection string
            // in arg 2: concatenating the connection string is not dynamic SQL.
            var range = SqlStatementRange(tokens, i, sink);
            if (range == null)
                continue;
            if (!HasSqlConcatenation(tokens, range.Value.Start, range.Value.End))
                continue;

            context.Report("Use parameterized queries to prevent SQL injection.", line);
        }
    }

    // Is the token at i an invocation name (followed by '(' on the same line)?
    private static bool IsInvocation(IReadOnlyList<Token> tokens, int i)
    {
        var line = tokens[i].Line;
        var j = i + 1;
        while (j < tokens.Count && tokens[j].Line == line && tokens[j].Text is "." or "?." or "!")
            j++;
        return j < tokens.Count && tokens[j].Line == line && tokens[j].Text == "(";
    }

    // The remaining token range [start, end) that holds the SQL statement for this sink.
    // Returns null when the sink is not a real query builder on this line (no parentheses).
    private static (int Start, int End)? SqlStatementRange(IReadOnlyList<Token> tokens, int i, string sink)
    {
        var line = tokens[i].Line;

        // Statement-shaped sinks: the command text is the assigned expression on this line.
        if (sink is "CommandText" or "ExecuteNonQuery" or "ExecuteScalar" or "ExecuteReader"
            || sink.StartsWith("FromSql", StringComparison.OrdinalIgnoreCase)
            || sink == "ExecuteQuery" || sink == "ExecuteUpdate")
        {
            var end = i;
            while (end + 1 < tokens.Count && tokens[end + 1].Line == line)
                end++;
            return (i, end + 1);
        }

        // Call/constructor shaped sinks: find the '(' after the method name on this same line, so a
        // `Dim command As SqlCommand` declaration is not paired with the constructor's parentheses
        // on the next line.
        var open = i + 1;
        while (open < tokens.Count && tokens[open].Line == line && tokens[open].Text != "(")
            open++;
        if (open >= tokens.Count || tokens[open].Line != line)
            return null;
        var close = MatchingClose(tokens, open);
        if (close < 0)
            return null;

        int sqlIndex = sink.EndsWith("Command", StringComparison.OrdinalIgnoreCase)
                       || sink.EndsWith("DataAdapter", StringComparison.OrdinalIgnoreCase) ? 1
            : sink == "ExecuteDataRow" ? 2              // MySqlHelper.ExecuteDataRow(connection, query, ...)
            : 1;                                        // SQLiteCommand.Execute(query, params, connection); FromSqlRaw(query, ...)
        return NthTopLevelArgument(tokens, open, close, sqlIndex);
    }

    // Indices of the matching ')' for the '(' at open.
    private static int MatchingClose(IReadOnlyList<Token> tokens, int open)
    {
        var depth = 0;
        for (var j = open; j < tokens.Count; j++)
        {
            if (tokens[j].Text == "(") depth++;
            else if (tokens[j].Text == ")")
            {
                depth--;
                if (depth == 0) return j;
            }
        }
        return -1;
    }

    // Token range [start, end) of the n-th top-level argument (1-based) of the paren group, or null.
    private static (int Start, int End)? NthTopLevelArgument(IReadOnlyList<Token> tokens, int open, int close, int n)
    {
        var start = open + 1;
        var count = 1;
        for (var j = open + 1; j <= close; j++)
        {
            if (tokens[j].Text == "(") { var m = MatchingClose(tokens, j); if (m > j) j = m; continue; }
            if (tokens[j].Text == ")" || tokens[j].Text == ",")
            {
                var end = j;
                if (count == n)
                {
                    // trim separators/space tokens (',') from the end; if empty, the arg is gone
                    while (end > start && (tokens[end - 1].Text == "," || tokens[end - 1].Text == " "))
                        end--;
                    return end > start ? (start, end) : null;
                }
                count++;
                start = j + 1;
            }
        }
        return null;
    }

    // A query built from a value: concatenation (& is VB, + is C#), string interpolation with a
    // hole, or a String.Concat/String.Format call, all restricted to [start, end).
    private static bool HasSqlConcatenation(IReadOnlyList<Token> line, int start, int end)
    {
        // interpolated strings: the tokenizer emits '$' as its own symbol and then the string, with
        // the {hole} kept in the value. A hole is a value fed into the query.
        for (var i = start; i < end - 1; i++)
        {
            if (line[i].Text == "$"
                && line[i + 1].Kind == TokenKind.String
                && line[i + 1].Text.Contains('{'))
                return true;
        }
        // binary concatenation: the value on either side of the operator feeds the query
        for (var i = start; i < end; i++)
        {
            var op = line[i].Text;
            if (op is "+" or "&" or "&=" or "+=")
            {
                if (i - 1 >= start && IsNonLiteralValue(line, i - 1)) return true;
                if (i + 1 < end && IsNonLiteralValue(line, i + 1)) return true;
            }
        }
        // String.Concat / String.Format within the range: any non-literal argument builds the query
        for (var i = start; i < end; i++)
        {
            var op = line[i].Text;
            if ((op == "Concat" || op == "Format") && i + 1 < end && line[i + 1].Text == "(")
            {
                var j = i + 2;
                while (j < end && line[j].Text != ")")
                {
                    if (IsNonLiteralValue(line, j)) return true;
                    j++;
                }
            }
        }
        return false;
    }

    private static bool IsNonLiteralValue(IReadOnlyList<Token> tokens, int i)
    {
        if (i < 0 || i >= tokens.Count)
            return false;
        var t = tokens[i];
        if (t.Kind != TokenKind.Identifier)
            return false;
        return !t.Text.Equals("True", StringComparison.OrdinalIgnoreCase)
            && !t.Text.Equals("False", StringComparison.OrdinalIgnoreCase)
            && !t.Text.Equals("Nothing", StringComparison.OrdinalIgnoreCase)
            && !t.Text.Equals("null", StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class CsWeakCryptoRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0003";
    public override string Name => "Use of weak cryptographic primitives";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Replace DES/TripleDES/RC2/MD5/SHA1 and ECB mode with modern algorithms.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => CSharpRuleSet.IsWord(t, ["DES", "TripleDES", "RC2", "RijndaelManaged", "MD5", "SHA1"])))
            context.Report("Replace weak cryptographic primitives with modern algorithms.", token.Line);
        foreach (var token in RuleMatchers.StringsContaining(context.Tokens, "ecb"))
            context.Report("Do not use ECB mode or insecure padding.", token.Line);
    }
}

public sealed class CsHardcodedCredentialsRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0004";
    public override string Name => "Hardcoded credentials";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Load credentials from a secure secret store.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!CSharpRuleSet.IsCredentialName(tokens[i])) continue;
            // The assignment has to be to this name. Scanning ahead for the next '=' crossed the
            // comma of an object initializer, so '.password = config.Password, .grant_type =
            // "password"' reported the grant type as a committed credential.
            if (i + 2 >= tokens.Count || tokens[i + 1].Text != "=")
                continue;
            if (tokens[i + 2].Kind != TokenKind.String || tokens[i + 2].Text.Length == 0)
                continue;

            context.Report("Hardcoded credentials must not be committed.", tokens[i].Line);
        }
        foreach (var s in RuleMatchers.StringsContaining(context.Tokens, "password=")
                     .Concat(RuleMatchers.StringsContaining(context.Tokens, "pwd=")))
            context.Report("Credentials embedded in configuration strings must not be used.", s.Line);
    }
}

public sealed class CsWeakRandomRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0005";
    public override string Name => "Use of non-cryptographic random generator";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use RandomNumberGenerator for security-sensitive values.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (CSharpRuleSet.IsWord(tokens[i], "new") && CSharpRuleSet.IsWord(tokens[i + 1], "Random"))
                context.Report("Use a cryptographically secure random generator.", tokens[i + 1].Line);
        }
    }
}

public sealed class CsDynamicTypeResolutionRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0006";
    public override string Name => "Dynamically resolved types";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Validate the type string before resolving it.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i + 1].Text != "(") continue;
            if ((CSharpRuleSet.IsMemberAccess(tokens, i, "Type", "GetType")
                 || CSharpRuleSet.IsMemberAccess(tokens, i, "Activator", "CreateInstance"))
                && !RuleMatchers.NextNonParenIsString(tokens, i))
                context.Report("Validate the type string before resolving it.", tokens[i].Line);
        }
    }
}

public sealed class CsXmlParsingRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0007";
    public override string Name => "XML parsing susceptible to XXE";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Configure XML parsing to disable external entities.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["XmlDocument", "XDocument"]))
            context.Report("Configure XML parsing to disable external entities.", token.Line);
    }
}

public sealed class CsAssemblyLoadRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0008";
    public override string Name => "Assembly loaded from dynamic path";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Validate the assembly path or name.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i + 1].Text != "(") continue;
            if ((CSharpRuleSet.IsMemberAccess(tokens, i, "Assembly", "Load")
                 || CSharpRuleSet.IsMemberAccess(tokens, i, "Assembly", "LoadFrom"))
                && !RuleMatchers.NextNonParenIsString(tokens, i))
                context.Report("Validate the assembly path or name.", tokens[i].Line);
        }
    }
}

public sealed class CsCleartextHttpRule : PatternRuleBase
{
    /// <summary>
    /// Hosts that only ever appear as identifiers. An XML namespace is a name, not an address:
    /// nothing is fetched from it, and changing it to https breaks every document that matches the
    /// schema.
    /// </summary>
    private static readonly string[] IdentifierHosts =
    [
        "schemas.xmlsoap.org", "www.w3.org", "schemas.microsoft.com", "tempuri.org",
        "schemas.datacontract.org", "docs.oasis-open.org", "www.opengis.net", "java.sun.com",
        "xmlns.oracle.com", "purl.org", "namespace"
    ];

    /// <summary>Attribute arguments that name an XML or SOAP namespace rather than an endpoint.</summary>
    private static readonly string[] NamespaceMarkers =
    [
        "Namespace", "RequestNamespace", "ResponseNamespace", "XmlType", "XmlRoot", "XmlElement",
        "XmlAttribute", "SoapDocumentMethod", "SoapRpcMethod", "WebServiceBinding", "ServiceContract",
        "OperationContract", "DataContract", "DataMember", "XmlSerializerFormat", "xmlns"
    ];

    public override string Key => "QG-CS-SEC-0009";
    public override string Name => "Cleartext HTTP";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = LanguageRuleSupport.Lines(context);
        foreach (var token in context.Tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            if (!CleartextProtocols.IsExposedAddress(token.Text, out var scheme, out var instead))
                continue;

            // A namespace declared on a serialization or web-service attribute is an identifier that
            // has to match the contract character for character. A generated SOAP proxy is full of
            // them, and every one of them was being reported as a transport problem.
            var line = token.Line - 1 < lines.Length && token.Line > 0 ? lines[token.Line - 1] : string.Empty;
            if (NamespaceMarkers.Any(m => line.Contains(m, StringComparison.Ordinal)))
                continue;

            context.Report(CleartextProtocols.Advice(scheme, instead), token.Line);
        }
    }
}

public sealed class CsInsecureCookieRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0010";
    public override string Name => "Insecure cookie configuration";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Set the Secure and HttpOnly flags on cookies.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!CSharpRuleSet.HasAny(lines[i], ["HttpCookie", "AppendCookie", "Response.Cookies"])) continue;
            if (CSharpRuleSet.HasAny(lines[i], ["HttpOnly", "Secure"])) continue;
            context.Report("Set the Secure and HttpOnly flags on cookies.", i + 1);
        }
    }
}

public sealed class CsUnsafeDeserializationRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0011";
    public override string Name => "Unsafe deserialization";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Avoid unsafe deserializers and validate the serialized data.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["BinaryFormatter", "LosFormatter", "ObjectStateFormatter", "NetDataContractSerializer", "JavaScriptSerializer"]))
            context.Report("Unsafe deserialization can lead to code execution.", token.Line);
    }
}

public sealed class CsSwitchDefaultRule : RuleBase
{
    public override string Key => "QG-CS-SML-0003";
    public override string Name => "Switch statements without a default clause";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Add a default clause to handle unexpected values.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var statement in context.Root.OfKind(QualityGuard.Core.Syntax.NodeKind.Match))
        {
            var body = statement.FirstChild(QualityGuard.Core.Syntax.NodeKind.Block);
            var sections = body?.ChildrenOf(QualityGuard.Core.Syntax.NodeKind.SwitchSection).ToList();
            if (sections is not { Count: > 0 })
                continue;
            if (sections.Any(section => section.Text is "default" or "_"))
                continue;

            context.Report("This switch has no default clause, so a value nobody listed passes "
                           + "through it without anything happening — and the next value added to "
                           + "the type it switches on will do the same.", statement.Line);
        }
    }
}

public sealed class CsGotoRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0004";
    public override string Name => "Goto statements";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Refactor to structured control flow.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => CSharpRuleSet.IsWord(t, "goto")))
            context.Report("Refactor to structured control flow.", token.Line);
    }
}

public sealed class CsGcCollectRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0006";
    public override string Name => "Explicit garbage collection";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Avoid calling GC.Collect explicitly.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i + 1].Text != "(") continue;
            if (CSharpRuleSet.IsMemberAccess(tokens, i, "GC", "Collect"))
                context.Report("Avoid calling GC.Collect explicitly.", tokens[i].Line);
        }
    }
}

public sealed class CsUnsafeBlockRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0007";
    public override string Name => "Unsafe code blocks";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Replace unsafe blocks with safe memory APIs when possible.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => CSharpRuleSet.IsWord(t, "unsafe")))
            context.Report("Avoid unsafe code blocks.", token.Line);
    }
}

public sealed class CsDateTimeNowRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0008";
    public override string Name => "Use DateTime.UtcNow instead of DateTime.Now";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use DateTime.UtcNow to avoid timezone-dependent results.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (CSharpRuleSet.IsMemberAccess(tokens, i, "DateTime", "Now"))
                context.Report("Use DateTime.UtcNow instead of DateTime.Now.", tokens[i].Line);
        }
    }
}

public sealed class CsAsyncVoidRule : PatternRuleBase
{
    public override string Key => "QG-CS-BUG-0001";
    public override string Name => "Async void methods";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Return Task from async methods instead of void.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (CSharpRuleSet.HasAny(lines[i], ["async void"]))
                context.Report("Async void methods terminate the process on exceptions.", i + 1);
        }
    }
}

public sealed class CsSsrRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0017";
    public override string Name => "Server-side request forgery via HTTP client";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Validate and allow list the target URL before issuing the request.";
    public override string[] Languages => ["cs", "vb"];

    private static readonly string[] RequestCalls =
    [
        "GetAsync", "PostAsync", "PutAsync", "PatchAsync", "DeleteAsync", "SendAsync",
        "GetStringAsync", "GetByteArrayAsync", "GetStreamAsync", "DownloadString", "DownloadFile",
        "OpenRead", "UploadString"
    ];

    /// <summary>
    /// Receivers that really do reach the network. Without this, an application service with a method
    /// called DeleteAsync — which every repository has — was reported as a request to a foreign host.
    /// </summary>
    private static readonly string[] Clients =
        ["HttpClient", "httpClient", "_httpClient", "client", "_client", "WebClient", "webClient",
         "http", "_http", "restClient", "_restClient"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        // a test names the address of the server it started itself
        if (LanguageRuleSupport.IsTestFile(context.File.Path, System.IO.Path.GetFileName(context.File.Path)))
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!RequestCalls.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;

            var receiver = SyntaxQuery.Receiver(call);
            var last = receiver.Split('.').LastOrDefault() ?? string.Empty;
            var isClient = Clients.Contains(last, StringComparer.OrdinalIgnoreCase)
                           || last.EndsWith("HttpClient", StringComparison.OrdinalIgnoreCase)
                           || context.Types.TypeOf(call.ChildAt(0)) is "HttpClient" or "WebClient";
            if (!isClient)
                continue;

            // a constant address is the code's own choice; the defect is letting the caller pick it
            var target = SyntaxQuery.ArgumentAt(call, 0);
            if (target == null || !context.IsTainted(target))
                continue;

            context.Report("The address of this request comes from data the caller controls, so the "
                           + "caller decides which host the server talks to — including one inside "
                           + "the network that is not reachable from outside. Check the target "
                           + "against a list of hosts you allow.", call.Range.StartLine);
        }
    }
}

public sealed class CsPathTraversalRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0018";
    public override string Name => "Path traversal via file operations";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Validate the path and restrict it to an allow listed directory.";
    public override string[] Languages => ["cs", "vb"];

    /// <summary>File and directory calls whose first argument is a path.</summary>
    private static readonly string[] PathCalls =
    [
        "Combine", "GetFullPath", "ReadAllText", "ReadAllBytes", "ReadAllLines", "OpenRead", "Open",
        "OpenText", "WriteAllText", "WriteAllBytes", "AppendAllText", "Delete", "Copy", "Move",
        "GetFiles", "GetDirectories", "CreateDirectory", "Create"
    ];

    private static readonly string[] PathOwners = ["Path", "File", "Directory", "FileInfo", "DirectoryInfo"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!PathCalls.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;
            var owner = SyntaxQuery.Receiver(call);
            if (!PathOwners.Any(o => owner == o || owner.EndsWith("." + o, StringComparison.Ordinal)))
                continue;

            // Reading a file is not a defect; reading the file the caller named is. Without a path
            // that comes from outside, this rule would report every program that touches the disk.
            var argument = SyntaxQuery.ArgumentAt(call, 0);
            if (argument == null || !context.IsTainted(argument))
                continue;

            context.Report($"The path handed to '{SyntaxQuery.InvokedName(call)}' is built from data "
                           + "the caller controls, so a name containing .. walks out of the directory "
                           + "this code meant to stay in. Resolve the path and check that it is still "
                           + "under the folder you allow.", call.Range.StartLine);
        }
    }
}

public sealed class CsLdapInjectionRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0019";
    public override string Name => "LDAP injection in directory filters";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Escape LDAP special characters or use a safe filter builder.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!CSharpRuleSet.HasAny(line, ["DirectorySearcher", "DirectoryEntry", "LdapConnection"])) continue;
            if (!CSharpRuleSet.HasAny(line, ["Filter"])) continue;
            if (!(line.Contains('+') || line.Contains('$') || CSharpRuleSet.HasAny(line, ["string.Format", "String.Format"]))) continue;
            context.Report("Use a parameterized LDAP filter to prevent injection.", i + 1);
        }
    }
}

public sealed class CsHeaderInjectionRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0020";
    public override string Name => "HTTP response header injection";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate header names and values and reject control characters.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!CSharpRuleSet.HasAny(line, [".Headers.Add", "AppendHeader", "Response.Headers[", ".Headers["])) continue;
            if (!(line.Contains('+') || line.Contains('$') || CSharpRuleSet.HasAny(line, ["string.Format", "String.Format"]))) continue;
            context.Report("Sanitize header values to prevent response splitting.", i + 1);
        }
    }
}

public sealed class CsCorsWildcardRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0021";
    public override string Name => "CORS policy allows any origin";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Restrict allowed origins to a specific list.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.StringsContaining(context.Tokens, "Access-Control-Allow-Origin"))
        {
            if (token.Text.Contains('*'))
                context.Report("Do not allow any origin in CORS.", token.Line);
        }
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i + 1].Text != "(") continue;
            // only the origin matters: any header and any method are ordinary once the origins are
            // named, and reporting all three turned one policy into three findings
            if (CSharpRuleSet.IsWord(tokens[i], ["AllowAnyOrigin", "SetIsOriginAllowedToAllowWildcardSubdomains"]))
                context.Report("The policy accepts every origin, so any site can have a visitor's "
                               + "browser call this API and read the answer. Name the origins you "
                               + "actually serve.", tokens[i].Line);
        }
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (CSharpRuleSet.HasAny(lines[i], ["WithOrigins"]) && lines[i].Contains('*'))
                context.Report("Restrict CORS origins instead of allowing any.", i + 1);
        }
    }
}

public sealed class CsXmlDeserializationRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0022";
    public override string Name => "Deserialization of untrusted XML";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Validate the XML input and restrict allowed types.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in RuleMatchers.Names(context.Tokens, ["XmlSerializer", "XmlTextReader", "XmlNodeReader"]))
            context.Report("Deserializing untrusted XML can lead to code execution.", token.Line);
    }
}

public sealed class CsHardcodedConnectionStringRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0023";
    public override string Name => "Hardcoded database connection string";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Load the connection string from a secure configuration store.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.String))
        {
            var hasServer = token.Text.Contains("Server=", StringComparison.OrdinalIgnoreCase)
                            || token.Text.Contains("Data Source=", StringComparison.OrdinalIgnoreCase);
            var hasSecret = token.Text.Contains("Password=", StringComparison.OrdinalIgnoreCase)
                            || token.Text.Contains("User ID=", StringComparison.OrdinalIgnoreCase)
                            || token.Text.Contains("Pwd=", StringComparison.OrdinalIgnoreCase)
                            || token.Text.Contains("Persist Security Info=", StringComparison.OrdinalIgnoreCase);
            if (hasServer && hasSecret)
                context.Report("Do not embed connection strings with credentials in code.", token.Line);
        }
    }
}

public sealed class CsInsecurePasswordValidationRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0024";
    public override string Name => "Insecure password validation policy";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Enforce a minimum password length of at least 8 characters.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (CSharpRuleSet.HasAny(line, ["PasswordStrengthValidator"]) && !line.Contains("RequiredLength"))
            {
                context.Report("Enforce a strong password policy.", i + 1);
                continue;
            }
            if (!line.Contains("RequiredLength")) continue;
            var idx = line.IndexOf("RequiredLength", StringComparison.Ordinal);
            var rest = line[(idx + "RequiredLength".Length)..];
            var num = "";
            for (var k = 0; k < rest.Length && char.IsDigit(rest[k]); k++) num += rest[k];
            if (num.Length > 0 && int.TryParse(num, out var length) && length < 8)
                context.Report("Minimum password length should be at least 8.", i + 1);
        }
    }
}

public sealed class CsWeakKeySizeRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0025";
    public override string Name => "Weak cryptographic key size";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use a key size of at least 2048 bits for RSA and 256 bits for ECDsa.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 2; i++)
        {
            if (CSharpRuleSet.IsWord(tokens[i], ["RSACryptoServiceProvider", "RSACng", "DSACryptoServiceProvider", "DSACng", "ECDsaCng"])
                && i > 0 && tokens[i - 1].Text == "new"
                && tokens[i + 1].Text == "("
                && tokens[i + 2].Kind == TokenKind.Number
                && int.TryParse(tokens[i + 2].Text, out var size) && size < 2048)
                context.Report("Use a key size of at least 2048 bits.", tokens[i].Line);
        }
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!lines[i].Contains("KeySize")) continue;
            if (!CSharpRuleSet.HasAny(lines[i], ["RSA", "DSA", "ECDsa", "ECDsa", "RSAEncryptionPadding"])) continue;
            var idx = lines[i].IndexOf('=');
            if (idx < 0) continue;
            var num = "";
            for (var k = idx + 1; k < lines[i].Length && char.IsDigit(lines[i][k]); k++) num += lines[i][k];
            if (num.Length > 0 && int.TryParse(num, out var size) && size < 2048)
                context.Report("Use a key size of at least 2048 bits.", i + 1);
        }
    }
}

public sealed class CsInsecureJwtRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0026";
    public override string Name => "Insecure JWT signing configuration";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use a strong asymmetric algorithm and never accept 'none'.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!CSharpRuleSet.HasAny(line, ["JwtSecurityTokenHandler", "TokenValidationParameters", "SignatureAlgorithm"])) continue;
            if (line.Contains("none", StringComparison.OrdinalIgnoreCase) && CSharpRuleSet.HasAny(line, ["Algorithm", "Jwt"]))
                context.Report("Never accept the 'none' JWT algorithm.", i + 1);
        }
    }
}

public sealed class CsDisabledCertValidationRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0027";
    public override string Name => "Certificate validation disabled";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Keep server certificate validation enabled.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Contains("DangerousAcceptAnyServerCertificateValidator", StringComparison.Ordinal))
            {
                context.Report("Do not accept any server certificate.", i + 1);
                continue;
            }
            if (!line.Contains("ServerCertificateCustomValidationCallback", StringComparison.Ordinal)) continue;
            if (line.Contains("return true", StringComparison.Ordinal) || line.Contains("=> true", StringComparison.Ordinal))
                context.Report("Do not disable server certificate validation.", i + 1);
        }
    }
}

public sealed class CsEntityFrameworkSqlInjectionRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0028";
    public override string Name => "SQL injection via interpolated EF queries";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Use parameterized queries and never build SQL from user input.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!CSharpRuleSet.HasAny(line, ["FromSqlInterpolated", "ExecuteSqlInterpolated", "InterpolatedQueryHandler"])) continue;
            if (!(line.Contains('$') || line.Contains('+') || context.IsTaintedLine(i + 1))) continue;
            context.Report("Do not build EF SQL queries from user input.", i + 1);
        }
    }
}

public sealed class CsOpenRedirectRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0029";
    public override string Name => "Open redirect from unvalidated input";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Validate that the redirect target is local or allow listed.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!CSharpRuleSet.HasAny(line, ["RedirectToAction", "RedirectToRoute", "RedirectToPage", "LocalRedirect"])) continue;
            if (!(line.Contains('+') || line.Contains('$') || context.IsTaintedLine(i + 1))) continue;
            context.Report("Validate the redirect target to prevent open redirects.", i + 1);
        }
    }
}

public sealed class CsExceptionInfoLeakRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0030";
    public override string Name => "Exception details exposed to the client";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Return a generic error message and log the exception details.";
    public override string[] Languages => ["cs", "vb"];

    /// <summary>What a caught exception can be asked for that a stranger should not read.</summary>
    private static readonly string[] Revealing = ["Message", "StackTrace", "ToString", "InnerException"];

    /// <summary>Calls that put their argument into the response.</summary>
    private static readonly string[] Responses =
        ["Content", "Json", "WriteAsync", "Write", "StatusCode", "Problem", "BadRequest", "NotFound",
         "Ok", "InternalServerError", "Send"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var catchClause in context.Root.OfKind(NodeKind.Catch))
        {
            var caught = catchClause.FirstChild(NodeKind.VariableDeclaration)?.Text;
            if (string.IsNullOrEmpty(caught))
                continue;
            var body = catchClause.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var read in Reads(body, caught))
            {
                if (!LeavesTheProcess(read))
                    continue;

                context.Report($"'{read.Text}' is handed back to the caller, and it carries the shape "
                               + "of the system with it: a file path, a query, a class name, sometimes "
                               + "a connection string. Log it, and answer with a message that says only "
                               + "that the request failed.", read.Range.StartLine);
                break;
            }
        }
    }

    /// <summary>Every place the caught exception is asked for something revealing.</summary>
    private static IEnumerable<SyntaxNode> Reads(SyntaxNode body, string caught)
    {
        foreach (var member in body.OfKind(NodeKind.MemberSelect))
        {
            var parts = member.Text.Split('.');
            if (parts.Length < 2 || parts[0] != caught)
                continue;
            if (!Revealing.Contains(parts[^1], StringComparer.Ordinal))
                continue;
            yield return member;
        }
    }

    /// <summary>
    /// Whether the value reaches the caller: returned, thrown back as a message, or handed to
    /// something that writes the response. A read that only feeds the logger is the correct thing
    /// to do and is left alone.
    /// </summary>
    private static bool LeavesTheProcess(SyntaxNode read)
    {
        for (var node = read.Parent; node != null; node = node.Parent)
        {
            if (node.Kind == NodeKind.Jump && node.Text == "return")
                return true;
            if (node.Kind == NodeKind.Invocation)
            {
                var name = SyntaxQuery.InvokedName(node);
                if (Responses.Contains(name, StringComparer.Ordinal))
                    return true;
                // a logger is the right destination, and it ends the search
                if (name.Length > 0)
                    return false;
            }
            if (node.Kind == NodeKind.Block)
                return false;
        }
        return false;
    }
}

public sealed class CsInsecureTempFileRule : PatternRuleBase
{
    public override string Key => "QG-CS-SEC-0031";
    public override string Name => "Insecure temporary file creation";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Create temp files in a secure directory with restrictive permissions.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 1; i < tokens.Count - 1; i++)
        {
            if (tokens[i + 1].Text != "(") continue;
            if (CSharpRuleSet.IsMemberAccess(tokens, i, "Path", "GetTempFileName")
                || CSharpRuleSet.IsMemberAccess(tokens, i, "Path", "GetTempPath"))
                context.Report("Use a secure temp directory with proper permissions.", tokens[i].Line);
        }
    }
}

public sealed class CsStringConcatInLoopRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0013";
    public override string Name => "String concatenation inside a loop";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use a StringBuilder instead of concatenating strings in a loop.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        var loopDepths = new HashSet<int>();
        var pendingLoop = false;
        var depth = 0;
        var paren = 0;
        for (var i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (t.Text == "(") { paren++; continue; }
            if (t.Text == ")") { paren--; continue; }
            if (t.Text == "{")
            {
                if (pendingLoop && paren == 0) { loopDepths.Add(depth); pendingLoop = false; }
                depth++;
                continue;
            }
            if (t.Text == "}")
            {
                depth--;
                loopDepths.Remove(depth);
                continue;
            }
            if (t.Text == ";" && paren == 0) { pendingLoop = false; continue; }
            if (CSharpRuleSet.IsWord(t, ["for", "foreach", "while", "do"])) { pendingLoop = true; continue; }
            if (t.Text == "+=" && loopDepths.Count > 0)
                context.Report("Use a StringBuilder for string concatenation in a loop.", t.Line);
        }
    }
}

public sealed class CsImplicitToStringRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0014";
    public override string Name => "Implicit ToString in string interpolation";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Call ToString with an explicit culture or format.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        foreach (var token in context.Tokens.Where(t => t.Kind == TokenKind.String && t.Text.Contains('{')))
        {
            var text = token.Text;
            for (var k = 0; k < text.Length; k++)
            {
                if (text[k] != '{')
                    continue;
                var end = text.IndexOf('}', k);
                if (end < 0)
                    break;
                var content = text[(k + 1)..end];
                k = end;

                // '{value:yyyy-MM-dd}' already says how to render it, and '{order.Id}' is how every
                // interpolated string is written. What is worth saying is a conversion asked for
                // without a culture, which is the one that changes answer between machines.
                if (content.Contains(':'))
                    continue;
                if (!content.Contains("ToString()", StringComparison.Ordinal))
                    continue;

                context.Report("This conversion uses whatever culture the machine happens to have, so "
                               + "the same value is written differently on a developer's laptop and on "
                               + "the server. Pass a culture, or a format.", token.Line);
                break;
            }
        }
    }
}

public sealed class CsAsyncWithoutAwaitRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0017";
    public override string Name => "Async method without an await expression";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Remove async or await an operation inside the method.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!CSharpRuleSet.IsWord(tokens[i], "async")) continue;
            if (CSharpRuleSet.HasAny(CSharpRuleSet.LineAt(context, tokens[i].Line), ["async void"])) continue;
            var open = -1;
            for (var j = i + 1; j < tokens.Count; j++)
            {
                if (tokens[j].Text == "{") { open = j; break; }
                if (tokens[j].Text is ";" or "=>") break;
            }
            if (open < 0) continue;
            var depth = 1;
            var hasAwait = false;
            for (var j = open + 1; j < tokens.Count && depth > 0; j++)
            {
                if (tokens[j].Text == "{") depth++;
                else if (tokens[j].Text == "}") depth--;
                else if (CSharpRuleSet.IsWord(tokens[j], "await")) hasAwait = true;
            }
            if (!hasAwait)
                context.Report("Await an operation inside this async method.", tokens[i].Line);
        }
    }
}

public sealed class CsCountInsteadOfAnyRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0018";
    public override string Name => "Count() used to test for emptiness";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use Any() instead of Count() when testing for emptiness.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            // '.Count' is a property: a list knows its own size, and comparing it costs nothing.
            // The call form is the one that walks the sequence to find out.
            // 'Count(predicate) > 0' walks the whole sequence to answer a question Any settles at
            // the first match, and it is the commoner form of the mistake
            if (!CSharpRuleSet.HasAny(line, [".Count()", "CountAsync()", ".Count ()", ".Count("])) continue;
            if (!(CSharpRuleSet.HasAny(line, ["> 0", "== 0", "!= 0", "> 0)", "== 0)"]))) continue;
            context.Report("Counting the whole sequence to find out whether it holds anything reads "
                           + "every element. 'Any()' stops at the first one.", i + 1);
        }
    }
}

public sealed class CsDivisionByZeroRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0019";
    public override string Name => "Integer division by a literal zero";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Guard against zero denominators.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Text is not ("/" or "%")) continue;
            if (tokens[i + 1].Kind != TokenKind.Number) continue;
            if (tokens[i + 1].Text != "0") continue;
            context.Report("Guard against division by zero.", tokens[i].Line);
        }
    }
}

public sealed class CsMissingDisposalRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0020";
    public override string Name => "Disposable resource not wrapped in using";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Wrap the resource in a using statement or call Dispose.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        // Types whose Dispose releases something the runtime cannot reclaim on its own. The ones
        // that only exist in memory — MemoryStream, StringReader, StringWriter — are deliberately
        // absent: their Dispose does nothing, and asking for it was every single report this rule
        // produced on a real repository.
        string[] disposables = ["FileStream", "StreamReader", "StreamWriter", "SqlConnection", "SqlCommand", "OleDbConnection", "HttpClient", "BinaryReader", "BinaryWriter", "SslStream", "TcpClient"];
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (CSharpRuleSet.HasAny(line, ["using", "await using", "return new", "=> new", "private", "public", "protected", "static"])) continue;
            var hasNew = disposables.Any(d => line.Contains("new " + d + "(") || line.Contains("new " + d + " ("));
            if (hasNew)
                context.Report("Dispose this resource or wrap it in a using statement.", i + 1);
        }
    }
}

public sealed class CsDeadStoreRule : PatternRuleBase
{
    public override string Key => "QG-CS-SML-0021";
    public override string Name => "Local variable assigned but never used";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Remove the unused local variable.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        string[] mods = ["private", "protected", "internal", "public", "static", "readonly", "const", "volatile"];
        string[] types = ["var", "int", "string", "bool", "double", "float", "decimal", "long", "short", "byte", "char", "object", "uint", "ulong", "sbyte", "ushort"];
        for (var i = 1; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Kind != TokenKind.Identifier) continue;
            if (tokens[i + 1].Text != "=") continue;
            var prev = tokens[i - 1];
            var isType = prev.Kind == TokenKind.Identifier || CSharpRuleSet.IsWord(prev.Text, types);
            if (!isType) continue;
            var hasMod = false;
            for (var k = Math.Max(0, i - 3); k < i; k++)
            {
                if (CSharpRuleSet.IsWord(tokens[k], mods)) { hasMod = true; break; }
            }
            if (hasMod) continue;
            var name = tokens[i].Text;
            var occurrences = tokens.Count(t => t.Kind == TokenKind.Identifier && t.Text == name);
            if (occurrences == 1)
                context.Report("This local variable is assigned but never used.", tokens[i].Line);
        }
    }
}

public sealed class CsNullReferenceRule : PatternRuleBase
{
    public override string Key => "QG-CS-BUG-0003";
    public override string Name => "Possible null reference dereference";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Check for null before dereferencing the value.";
    public override string[] Languages => ["cs", "vb"];

    /// <summary>Calls that answer with null when they find nothing.</summary>
    private static readonly string[] MayReturnNull =
    [
        "FirstOrDefault", "SingleOrDefault", "LastOrDefault", "ElementAtOrDefault",
        "FirstOrDefaultAsync", "SingleOrDefaultAsync", "LastOrDefaultAsync", "Find", "FindAsync"
    ];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var block in context.Root.OfKind(NodeKind.Block))
        {
            var statements = block.Children;
            for (var i = 0; i < statements.Count - 1; i++)
            {
                // the value comes back possibly null and is given a name
                var declaration = statements[i];
                if (declaration.Kind != NodeKind.VariableDeclaration || declaration.Text.Length == 0)
                    continue;
                var producer = declaration.OfKind(NodeKind.Invocation)
                    .FirstOrDefault(c => MayReturnNull.Contains(SyntaxQuery.InvokedName(c), StringComparer.Ordinal));
                if (producer == null)
                    continue;

                var name = declaration.Text;
                var next = statements[i + 1];

                // Anything that tests the value stops the search, and a statement that tests it is
                // not a defect whatever else it does: 'return x != null && x.P' checks before it
                // reads, and so does 'if (x is null) return;'.
                if (Tests(next, name))
                    continue;

                // 'var x = list.FirstOrDefault()?.Name;' answers the question where it is asked
                if (declaration.OfKind(NodeKind.MemberSelect).Any(m => m.Tokens.Any(t => t.Text == "?.")))
                    continue;

                var dereference = next.OfKind(NodeKind.MemberSelect)
                    .FirstOrDefault(m => m.ChildAt(0) is { Kind: NodeKind.Identifier } target
                                         && target.Text == name
                                         // '?.' already answers the question
                                         && !m.Tokens.Any(t => t.Text == "?."));
                if (dereference == null)
                    continue;

                context.Report($"'{name}' is null when nothing is found, and the next line reads a "
                               + "member of it without checking. Test it first, or use the "
                               + "null-conditional operator.", dereference.Range.StartLine);
            }
        }
    }

    /// <summary>Whether a statement checks the name against null before using it.</summary>
    private static bool Tests(SyntaxNode statement, string name)
    {
        if (statement.Kind is NodeKind.If or NodeKind.Match)
            return true;
        foreach (var node in statement.DescendantsAndSelf())
        {
            // '!=', '==', 'is' and the null-conditional all read as a check of the same name
            var checks = node.Kind switch
            {
                NodeKind.Binary => node.Text is "==" or "!=" or "&&" or "||" or "??" or "is",
                NodeKind.Conditional => true,
                _ => node.Text is "?." or "??"
            };
            if (!checks)
                continue;
            if (node.DescendantsAndSelf().Any(n => n.Kind == NodeKind.Identifier && n.Text == name))
                return true;
        }
        return false;
    }
}

public sealed class CsUploadedFileNameRule : PatternRuleBase
{
    /// <summary>Calls that turn a string into a place on disk.</summary>
    private static readonly string[] PathCalls =
        ["Combine", "GetFullPath", "Create", "WriteAllBytes", "WriteAllText", "OpenWrite", "Open",
         "CreateText", "AppendAllText", "Move", "Copy", "SaveAs", "SaveAsAsync"];

    public override string Key => "QG-CS-SEC-0066";
    public override string Name => "An uploaded file should not name its own place on disk";
    public override Severity Severity => Severity.Critical;
    public override IssueKind Kind => IssueKind.Vulnerability;
    public override string RemediationEffort => "30min";
    public override string FixAdvice => "Generate the stored name yourself and keep the original only as data.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var call in SyntaxQuery.Invocations(context.Root))
        {
            if (!PathCalls.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                continue;

            // Storing the name the client sent is ordinary — it is data about the upload. The defect
            // is letting that name decide where the bytes land, because it can contain a path.
            var fromClient = SyntaxQuery.Arguments(call)
                .Any(a => a.DescendantsAndSelf().Any(n => n.Kind == NodeKind.MemberSelect
                                                          && n.Text.EndsWith(".FileName", StringComparison.Ordinal)));
            if (!fromClient)
                continue;

            context.Report("The name the client sent decides where this file is written, and a name "
                           + "can contain a path: '..' walks out of the folder, and a familiar name "
                           + "overwrites something that was already there. Generate the stored name "
                           + "yourself and keep the original only as data.", call.Range.StartLine);
        }
    }
}

public sealed class CsFloatEqualityRule : PatternRuleBase
{
    public override string Key => "QG-CS-BUG-0004";
    public override string Name => "Floating-point values compared with ==";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Compare floating-point values using a tolerance.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 1; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Text is not ("==" or "!=")) continue;
            var left = tokens[i - 1];
            var right = tokens[i + 1];
            bool IsFloat(Token t) => t.Kind == TokenKind.Number
                                     && (t.Text.Contains('.') || t.Text.EndsWith('f') || t.Text.EndsWith('F') || t.Text.EndsWith('d') || t.Text.EndsWith('D'));
            if (IsFloat(left) || IsFloat(right))
                context.Report("Compare floating-point values with a tolerance.", tokens[i].Line);
        }
    }
}

public sealed class CsCollectionModifiedRule : PatternRuleBase
{
    /// <summary>Calls that change the shape of a collection while something is walking it.</summary>
    private static readonly string[] Structural =
        ["Add", "AddRange", "Remove", "RemoveAt", "RemoveAll", "RemoveRange", "Clear", "Insert",
         "InsertRange", "Push", "Pop", "Enqueue", "Dequeue"];

    public override string Key => "QG-CS-BUG-0005";
    public override string Name => "A collection should not change while it is being walked";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Iterate a copy, or collect the changes and apply them after the loop.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var loop in context.Root.OfKind(NodeKind.Loop))
        {
            // the collection being walked is the last name in the header, before the body
            var walked = WalkedCollection(loop);
            if (walked.Length == 0)
                continue;
            var body = loop.FirstChild(NodeKind.Block);
            if (body == null)
                continue;

            foreach (var call in SyntaxQuery.Invocations(body))
            {
                if (!Structural.Contains(SyntaxQuery.InvokedName(call), StringComparer.Ordinal))
                    continue;
                // it is only a defect when the collection changed is the one being walked
                if (SyntaxQuery.Receiver(call) != walked)
                    continue;

                context.Report($"'{walked}' is being walked by this loop and changed inside it, so the "
                               + "enumerator is invalidated and the next step throws. Iterate a copy, "
                               + "or collect the changes and apply them after the loop.",
                    call.Range.StartLine);
            }
        }
    }

    /// <summary>The name of the collection a foreach walks, or empty when it is not a plain name.</summary>
    private static string WalkedCollection(SyntaxNode loop)
    {
        var body = loop.FirstChild(NodeKind.Block);
        var header = loop.Children.Where(c => c != body).ToList();
        if (header.Count == 0)
            return string.Empty;

        // 'foreach (var item in items)' keeps the source as the last thing before the body
        var source = header[^1];
        return source.Kind switch
        {
            NodeKind.Identifier => source.Text,
            NodeKind.MemberSelect => SyntaxQuery.DottedName(source),
            _ => string.Empty
        };
    }
}

public sealed class CsAsyncSuffixRule : PatternRuleBase
{
    private static readonly string[] Awaitable = ["Task", "ValueTask", "IAsyncEnumerable"];

    /// <summary>
    /// Methods whose name is fixed by something outside the class: the framework calls them by that
    /// name, and renaming one breaks the binding rather than improving it.
    /// </summary>
    private static readonly string[] Reserved =
        ["Main", "MoveNextAsync", "DisposeAsync", "InvokeAsync", "Invoke", "ExecuteAsync",
         "OnInitialized", "OnParametersSet", "OnAfterRender", "SetParametersAsync"];

    public override string Key => "QG-CS-SML-0053";
    public override string Name => "Asynchronous methods should be named accordingly";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var method in context.Root.OfKind(NodeKind.FunctionDeclaration))
        {
            var name = method.Text;
            if (name.Length == 0 || name.EndsWith("Async", StringComparison.Ordinal))
                continue;
            if (Reserved.Contains(name, StringComparer.Ordinal))
                continue;

            var returned = method.FirstChild(NodeKind.TypeReference)?.Text;
            if (returned == null || !Awaitable.Any(t => returned == t
                    || returned.StartsWith(t + "<", StringComparison.Ordinal)))
                continue;

            // An override, an interface implementation and an event handler are all named by
            // somebody else. The modifier says so for the first; for the rest the attribute does,
            // because a framework that routes to a method also decorates it.
            var modifiers = method.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (modifiers.Contains("override") || modifiers.Contains("partial"))
                continue;
            if (method.ChildrenOf(NodeKind.Attribute).Any() || method.ChildrenOf(NodeKind.AttributeList).Any())
                continue;
            // a method with no body is a declaration in an interface: the implementation carries the name
            if (SyntaxQuery.Body(method) == null)
                continue;

            context.Report(method, $"'{name}' hands back something that has to be awaited, and its name "
                                   + "does not say so. A caller who forgets the await gets a task "
                                   + "nobody watches, and the exception it carries is never raised.");
        }
    }
}

public sealed class CsMutableCollectionPropertyRule : PatternRuleBase
{
    /// <summary>Collection types a caller can change through the reference they are handed.</summary>
    /// <summary>Names a type ends with when it exists to carry data across a boundary.</summary>
    private static readonly string[] DataCarrierSuffixes =
        ["Dto", "DTO", "Model", "ViewModel", "Request", "Response", "Entity", "Args", "Options",
         "Settings", "Config", "Configuration", "Payload", "Message", "Command", "Query", "Result",
         "Record", "Info", "Data"];

    private static readonly string[] Mutable =
        ["List", "IList", "ICollection", "Collection", "Dictionary", "IDictionary", "HashSet",
         "ISet", "SortedList", "SortedDictionary", "ObservableCollection", "Queue", "Stack"];

    public override string Key => "QG-CS-SML-0057";
    public override string Name => "Collections exposed by properties should be read-only";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "20min";
    public override string[] Languages => ["cs"];

    public override void Execute(IRuleContext context)
    {
        if (!context.Tree.HasDedicatedParser)
            return;

        foreach (var property in context.Root.OfKind(NodeKind.PropertyDeclaration))
        {
            var modifiers = property.ChildrenOf(NodeKind.Modifier).Select(m => m.Text).ToArray();
            if (!modifiers.Contains("public") && !modifiers.Contains("protected"))
                continue;

            var declared = property.FirstChild(NodeKind.TypeReference)?.Text;
            if (declared == null)
                continue;
            var bare = declared.Split('<')[0].Split('.').Last();
            if (!Mutable.Contains(bare, StringComparer.Ordinal))
                continue;

            // A type that carries data is filled by whoever deserialises it, and that needs the
            // setter. The name says what the type is for, and every project in the world names them
            // the same way.
            var owner = property.Ancestor(NodeKind.ClassDeclaration)?.Text ?? string.Empty;
            if (DataCarrierSuffixes.Any(suffix => owner.EndsWith(suffix, StringComparison.Ordinal)))
                continue;

            // A framework can require the shape: an ORM writes into a navigation collection through
            // the setter, and a component receives its parameters the same way. Both are declared
            // that way on purpose, and neither is the author's choice to make.
            if (property.ChildrenOf(NodeKind.Attribute).Any())
                continue;
            if (modifiers.Contains("virtual") || bare is "ICollection" or "IDictionary" or "ISet")
                continue;

            // a setter hands the whole collection over; without one the reference is still shared,
            // but replacing it is at least out of reach
            var setter = property.OfKind(NodeKind.Accessor)
                .FirstOrDefault(a => a.Text is "set" or "init");
            if (setter == null)
                continue;
            if (setter.ChildrenOf(NodeKind.Modifier).Any(m => m.Text is "private" or "protected" or "internal"))
                continue;
            if (setter.Text == "init")
                continue;

            context.Report(property, $"'{property.Text}' hands out a {bare} and lets a caller replace "
                                     + "it. Anything they add or remove skips the checks this type "
                                     + "performs, and whoever held the previous reference keeps "
                                     + "watching a collection nobody updates. Expose a read-only view "
                                     + "and keep the mutable one private.");
        }
    }
}

public sealed class CsTaskBlockingRule : PatternRuleBase
{
    public override string Key => "QG-CS-BUG-0006";
    public override string Name => "Blocking call on a Task";
    public override Severity Severity => Severity.Major;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "20min";
    public override string FixAdvice => "Use await instead of Result, Wait or GetAwaiter().GetResult().";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 1; i < tokens.Count - 1; i++)
        {
            if (tokens[i - 1].Text != ".") continue;
            if (CSharpRuleSet.IsWord(tokens[i], ["Wait", "WaitAll", "WaitAny"]) && tokens[i + 1].Text == "(")
            {
                context.Report("Await the Task instead of blocking with Wait.", tokens[i].Line);
                continue;
            }
            if (tokens[i].Text == "Result" && i >= 2 && tokens[i - 2].Kind == TokenKind.Identifier
                && tokens[i - 2].Text.IndexOf("task", StringComparison.OrdinalIgnoreCase) >= 0)
                context.Report("Await the Task instead of blocking on Result.", tokens[i].Line);
            if (tokens[i].Text == "GetResult" && tokens[i + 1].Text == "(")
                context.Report("Await the Task instead of calling GetResult.", tokens[i].Line);
        }
    }
}

public sealed class CsOffByOneLoopRule : PatternRuleBase
{
    public override string Key => "QG-CS-BUG-0007";
    public override string Name => "IndexOutOfRange risk in loop bound";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.Bug;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Use < instead of <= in the loop condition.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var lines = CSharpRuleSet.LinesOf(context);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!line.Contains("for (")) continue;
            if (!line.Contains("<=")) continue;
            if (!(line.Contains(".Length") || line.Contains(".Count"))) continue;
            context.Report("The loop bound may cause an index out of range.", i + 1);
        }
    }
}

public sealed class CsPascalCaseMethodRule : PatternRuleBase
{
    public override string Key => "QG-CS-CNV-0002";
    public override string Name => "Method names should use PascalCase";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename the method to PascalCase.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        string[] types = ["void", "int", "string", "bool", "double", "float", "decimal", "long", "short", "byte", "char", "object", "uint", "ulong", "sbyte", "ushort"];
        for (var i = 1; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Kind != TokenKind.Identifier) continue;
            if (tokens[i + 1].Text != "(") continue;
            var name = tokens[i].Text;
            if (name.Length == 0 || char.IsUpper(name[0])) continue;
            var prev = tokens[i - 1];
            if (prev.Text is "." or "new" or "(" or "=" or ";" or "{" or "}" or "return") continue;
            var isType = prev.Kind == TokenKind.Identifier || CSharpRuleSet.IsWord(prev.Text, types)
                         || CSharpRuleSet.IsWord(prev, ["public", "private", "protected", "internal", "static", "async", "virtual", "override", "abstract", "sealed"]);
            if (!isType) continue;
            context.Report("Method names should use PascalCase.", tokens[i].Line);
        }
    }
}

public sealed class CsCamelCaseLocalRule : PatternRuleBase
{
    public override string Key => "QG-CS-CNV-0003";
    public override string Name => "Local variables should use camelCase";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Rename the local variable to camelCase.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 1; i < tokens.Count - 2; i++)
        {
            if (!CSharpRuleSet.IsWord(tokens[i], "var")) continue;
            var name = tokens[i + 1];
            if (name.Kind != TokenKind.Identifier) continue;
            if (name.Text.Length == 0 || char.IsLower(name.Text[0])) continue;
            if (tokens[i + 2].Text is not ("=" or ";")) continue;
            if (CSharpRuleSet.HasAny(CSharpRuleSet.LineAt(context, tokens[i].Line), ["public", "private", "protected", "internal", "static", "readonly", "const"])) continue;
            context.Report("Local variables should use camelCase.", name.Line);
        }
    }
}

public sealed class CsInterfacePrefixRule : PatternRuleBase
{
    public override string Key => "QG-CS-CNV-0004";
    public override string Name => "Interface names should start with I";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "10min";
    public override string FixAdvice => "Prefix the interface name with I.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (!CSharpRuleSet.IsWord(tokens[i], "interface")) continue;
            var name = tokens[i + 1];
            if (name.Kind != TokenKind.Identifier) continue;
            if (name.Text.StartsWith('I')) continue;
            context.Report("Interface names should start with the I prefix.", name.Line);
        }
    }
}

public sealed class CsConstNamingRule : PatternRuleBase
{
    public override string Key => "QG-CS-CNV-0005";
    public override string Name => "Constants should follow the naming convention";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "5min";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var tokens = context.Tokens;
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (!CSharpRuleSet.IsWord(tokens[i], "const")) continue;
            var j = i + 1;
            if (j >= tokens.Count || tokens[j].Kind is not (TokenKind.Identifier or TokenKind.Keyword)) continue;
            j++;
            if (j >= tokens.Count || tokens[j].Kind != TokenKind.Identifier) continue;
            var name = tokens[j].Text;
            // PascalCase is the .NET convention; UPPER_CASE is accepted for interop constants
            var isPascalCase = char.IsUpper(name[0]) && !name.Contains('_');
            var isUpperCase = name == name.ToUpperInvariant();
            if (!isPascalCase && !isUpperCase)
                context.Report("Name this constant in PascalCase.", tokens[j].Line);
        }
    }
}

/// <summary>
/// A comment marker with nothing after it. Read line by line this is one of the loudest rules there
/// is: every licence header separates its paragraphs with a bare '//', and on a real repository that
/// was thousands of reports for text that is deliberately blank. A comment is a block, and a block
/// that says something is not empty — only the marker that stands entirely alone is.
/// </summary>
public sealed class CsEmptyCommentRule : RuleBase
{
    public override string Key => "QG-CS-SML-0075";
    public override string Name => "Empty comments should be removed";
    public override Severity Severity => Severity.Minor;
    public override IssueKind Kind => IssueKind.CodeSmell;
    public override string RemediationEffort => "2min";
    public override string FixAdvice => "Remove the marker, or write the explanation the code needs.";
    public override string[] Languages => ["cs", "vb"];

    public override void Execute(IRuleContext context)
    {
        var comments = context.Tokens.Where(t => t.Kind == TokenKind.Comment).ToList();
        for (var i = 0; i < comments.Count; i++)
        {
            if (Says(comments[i]))
                continue;
            // a bare marker inside a run of comment lines is a paragraph break in one text
            if (i > 0 && comments[i - 1].Line >= comments[i].Line - 1)
                continue;
            if (i + 1 < comments.Count && comments[i + 1].Line <= comments[i].Line + 1)
                continue;

            context.Report("This comment marker has nothing after it, so the line only says that an "
                           + "explanation was meant to be here. Write it or take the marker away.",
                comments[i].Line);
        }
    }

    /// <summary>
    /// Whether the line says anything. A run of dashes says "a section starts here", which is a
    /// decision someone made about the shape of the file — it is decoration, not a marker left
    /// empty, and reporting it was most of what this rule found on a real application.
    /// </summary>
    private static bool Says(Token comment)
    {
        var text = comment.Text.Trim(MarkerCharacters);
        return text.Length > 0;
    }

    private static readonly char[] MarkerCharacters =
        ['/', '\'', '*', '#', ' ', '\t', '\r', '\n'];
}
