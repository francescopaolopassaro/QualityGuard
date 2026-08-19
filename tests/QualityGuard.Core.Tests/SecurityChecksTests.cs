using Xunit;

namespace QualityGuard.Core.Tests;

/// <summary>
/// Cryptography that compiles and protects nothing. Each pair below is the same call written twice —
/// once with the value fixed in the source, once with it produced at run time — because what these
/// rules must never do is report the correct version.
/// </summary>
public class SecurityChecksTests
{
    private static IReadOnlyList<int> Lines(string file, string code, string rule)
        => Analyze.LinesOf(Analyze.WithRules(file, code, rule), rule);

    [Fact]
    public void A_salt_written_in_the_source_is_reported_and_one_passed_in_is_not()
    {
        var code = """
            public class Crypto
            {
                private static readonly byte[] FixedSalt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

                public byte[] Bad(string password)
                {
                    var derive = new Rfc2898DeriveBytes(password, FixedSalt, 10000);
                    return derive.GetBytes(32);
                }

                public byte[] Good(string password, byte[] salt)
                {
                    var derive = new Rfc2898DeriveBytes(password, salt, 100000);
                    return derive.GetBytes(32);
                }
            }
            """;
        Assert.Single(Lines("Crypto.cs", code, "QG-CS-SEC-0067"));
    }

    [Fact]
    public void An_initialisation_vector_of_zeros_is_reported()
    {
        var code = """
            public class Crypto
            {
                public byte[] Encrypt(byte[] key, byte[] data)
                {
                    using var aes = Aes.Create();
                    var iv = new byte[16];
                    var encryptor = aes.CreateEncryptor(key, iv);
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }

                public byte[] Fresh(byte[] key, byte[] data, byte[] iv)
                {
                    using var aes = Aes.Create();
                    var encryptor = aes.CreateEncryptor(key, iv);
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
            """;
        Assert.Single(Lines("Crypto.cs", code, "QG-CS-SEC-0071"));
    }

    [Fact]
    public void A_signing_key_in_the_source_is_reported()
    {
        var code = """
            public class Tokens
            {
                public string Issue()
                {
                    var handler = new JwtSecurityTokenHandler();
                    return handler.WriteToken("payload", "s3cr3t-signing-key-1234");
                }
            }
            """;
        Assert.NotEmpty(Lines("Tokens.cs", code, "QG-CS-SEC-0082"));
    }

    [Fact]
    public void A_file_that_has_nothing_to_do_with_tokens_is_left_alone()
    {
        // 'encode' and 'sign' are ordinary words: without a token anywhere the rule has no subject
        var code = """
            public class Encoder
            {
                public string Run(string payload)
                {
                    return Convert.ToBase64String(Encoding.UTF8.GetBytes(payload + "-suffix-1234"));
                }
            }
            """;
        Assert.Empty(Lines("Encoder.cs", code, "QG-CS-SEC-0082"));
    }

    [Fact]
    public void A_cipher_left_in_codebook_mode_is_reported()
    {
        var code = """
            class Crypto {
                fun encrypt(): Cipher {
                    val weak = Cipher.getInstance("AES/ECB/PKCS5Padding")
                    val strong = Cipher.getInstance("AES/GCM/NoPadding")
                    return weak
                }
            }
            """;
        // GCM authenticates, so its 'NoPadding' is the correct spelling and must stay quiet
        Assert.Single(Lines("Crypto.kt", code, "QG-KT-SEC-0043"));
    }
}
