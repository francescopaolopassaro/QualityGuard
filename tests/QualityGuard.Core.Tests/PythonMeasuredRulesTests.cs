using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// The Python rules chosen by measuring against an annotated reference corpus. Each one is pinned
/// with the defect it must find and the shape it must leave alone.
/// </summary>
public class PythonMeasuredRulesTests
{
    private static IReadOnlyList<int> Lines(string code, string rule, string file = "service.py")
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_statement_that_computes_and_discards_is_reported()
    {
        Assert.NotEmpty(Lines("def go(a, b):\n    a == b\n    return 1\n", "QG-PY-BUG-0149"));
        Assert.Empty(Lines("def go(a, b):\n    c = a == b\n    return c\n", "QG-PY-BUG-0149"));
        // a docstring and an ellipsis body are statements on purpose
        Assert.Empty(Lines("def go():\n    \"the doc\"\n    return 1\n", "QG-PY-BUG-0149"));
    }

    [Fact]
    public void Doubled_parentheses_are_reported()
    {
        Assert.NotEmpty(Lines("x = ((1 + 2))\n", "QG-PY-CNV-0008"));
        Assert.Empty(Lines("x = (1 + 2)\n", "QG-PY-CNV-0008"));
        // a call taking a tuple opens two parentheses for a reason
        Assert.Empty(Lines("x = fn((1, 2))\n", "QG-PY-CNV-0008"));
    }

    [Fact]
    public void A_type_variable_named_differently_is_reported()
    {
        Assert.NotEmpty(Lines("from typing import TypeVar\nMyType = TypeVar(\"T\")\n", "QG-PY-CNV-0009"));
        Assert.Empty(Lines("from typing import TypeVar\nT = TypeVar(\"T\")\n", "QG-PY-CNV-0009"));
    }

    [Fact]
    public void A_special_method_returning_the_wrong_type_is_reported()
    {
        Assert.NotEmpty(Lines("class A:\n    def __bool__(self):\n        return \"yes\"\n",
            "QG-PY-BUG-0150"));
        Assert.Empty(Lines("class A:\n    def __bool__(self):\n        return True\n",
            "QG-PY-BUG-0150"));
        // anything computed is left alone: the engine cannot promise its type
        Assert.Empty(Lines("class A:\n    def __bool__(self):\n        return self.ready\n",
            "QG-PY-BUG-0150"));
    }

    [Fact]
    public void An_assertion_on_a_constant_is_reported()
    {
        Assert.NotEmpty(Lines("class T:\n    def test_one(self):\n        self.assertTrue(True)\n",
            "QG-PY-BUG-0151"));
        Assert.Empty(Lines("class T:\n    def test_one(self):\n        self.assertTrue(result)\n",
            "QG-PY-BUG-0151"));
    }

    [Fact]
    public void A_comparison_inside_assertTrue_is_reported()
    {
        Assert.NotEmpty(Lines("class T:\n    def test_one(self):\n        self.assertTrue(a == b)\n",
            "QG-PY-SML-0251"));
        Assert.Empty(Lines("class T:\n    def test_one(self):\n        self.assertEqual(a, b)\n",
            "QG-PY-SML-0251"));
    }

    [Fact]
    public void An_obsolete_protocol_constant_is_reported()
    {
        Assert.NotEmpty(Lines("import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n", "QG-PY-SEC-0085"));
        Assert.Empty(Lines("import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n",
            "QG-PY-SEC-0085"));
    }

    [Fact]
    public void A_literal_salt_is_reported()
    {
        Assert.NotEmpty(Lines("import hashlib\nh = hashlib.pbkdf2_hmac(\"sha256\", pw, b\"static\", 1000)\n",
            "QG-PY-SEC-0086"));
        Assert.Empty(Lines("import hashlib, os\nh = hashlib.pbkdf2_hmac(\"sha256\", pw, os.urandom(16), 1000)\n",
            "QG-PY-SEC-0086"));
    }

    [Fact]
    public void A_token_decoded_without_verification_is_reported()
    {
        Assert.NotEmpty(Lines("import jwt\nd = jwt.decode(token, verify=False)\n", "QG-PY-SEC-0087"));
        Assert.NotEmpty(Lines("import jwt\nd = jwt.process_jwt(token)\n", "QG-PY-SEC-0087"));
        Assert.Empty(Lines("import jwt\nd = jwt.decode(token, key, algorithms=[\"HS256\"])\n",
            "QG-PY-SEC-0087"));
    }

    [Fact]
    public void A_wildcard_origin_is_reported()
    {
        Assert.NotEmpty(Lines("headers[\"Access-Control-Allow-Origin\"] = \"*\"\n", "QG-PY-SEC-0088"));
        Assert.Empty(Lines("headers[\"Access-Control-Allow-Origin\"] = \"https://acme.example\"\n",
            "QG-PY-SEC-0088"));
    }

    [Fact]
    public void A_password_hashed_with_a_fast_digest_is_reported()
    {
        Assert.NotEmpty(Lines("import hashlib\nh = hashlib.md5(password)\n", "QG-PY-SEC-0089"));
        // a digest of something that is not a password is a different thing
        Assert.Empty(Lines("import hashlib\nh = hashlib.md5(contents)\n", "QG-PY-SEC-0089"));
    }

    [Fact]
    public void A_constant_operand_in_a_condition_is_reported()
    {
        Assert.NotEmpty(Lines("def go(a):\n    if a and True:\n        return 1\n    return 0\n",
            "QG-PY-BUG-0152"));
        Assert.Empty(Lines("def go(a, b):\n    if a and b:\n        return 1\n    return 0\n",
            "QG-PY-BUG-0152"));
    }
}
