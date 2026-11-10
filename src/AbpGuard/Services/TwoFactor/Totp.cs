using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace AbpGuard.Services.TwoFactor;

/// <summary>
/// Time-based one-time codes (RFC 6238, with HOTP's RFC 4226): HMAC-SHA1, six digits, 30-second steps, as every
/// authenticator app reads them from an <c>otpauth://</c> address. A code is taken from the step before or after too,
/// for clocks a little apart, and is good once: the step it matched must be later than the last one used.
/// </summary>
public static class Totp
{
    public const int Digits = 6;
    public const int PeriodSeconds = 30;
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>A new secret: 160 bits, as RFC 4226 recommends for SHA-1.</summary>
    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(20);

    public static long StepAt(DateTimeOffset time) => time.ToUnixTimeSeconds() / PeriodSeconds;

    /// <summary>The code for a time step.</summary>
    public static string Code(byte[] secret, long step, int digits = Digits)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> hash = stackalloc byte[20];
#pragma warning disable CA5350 // RFC 6238's algorithm, which every authenticator app uses by default; not a hash for integrity
        HMACSHA1.HashData(secret, counter, hash);
#pragma warning restore CA5350
        int offset = hash[^1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        int modulo = (int)Math.Pow(10, digits);
        return (binary % modulo).ToString(System.Globalization.CultureInfo.InvariantCulture).PadLeft(digits, '0');
    }

    /// <summary>The step a code matches, one step either side of now and later than <paramref name="lastStep"/>; null when none.</summary>
    public static long? Verify(byte[] secret, string? code, DateTimeOffset now, long lastStep)
    {
        string typed = new((code ?? "").Where(char.IsAsciiDigit).ToArray());
        if (typed.Length != Digits)
        {
            return null;
        }

        long current = StepAt(now);
        for (long step = current - 1; step <= current + 1; step++)
        {
            if (step > lastStep && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Code(secret, step)), Encoding.ASCII.GetBytes(typed)))
            {
                return step;
            }
        }

        return null;
    }

    /// <summary>The address an authenticator app reads, from a QR code or typed in.</summary>
    public static string Address(string issuer, string account, byte[] secret) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}?secret={ToBase32(secret)}&issuer={Uri.EscapeDataString(issuer)}"
        + $"&algorithm=SHA1&digits={Digits}&period={PeriodSeconds}";

    public static string ToBase32(byte[] data)
    {
        StringBuilder text = new((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                text.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            text.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return text.ToString();
    }

    public static byte[] FromBase32(string text)
    {
        List<byte> data = [];
        int buffer = 0, bits = 0;
        foreach (char c in text.ToUpperInvariant().Where(c => c is not ('=' or ' ' or '-')))
        {
            int value = Base32Alphabet.IndexOf(c);
            if (value < 0)
            {
                throw new FormatException("Not base32.");
            }

            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                data.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }

        return [.. data];
    }
}
