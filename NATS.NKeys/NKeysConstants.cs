namespace NATS.NKeys;

internal static class NKeysConstants
{
    /// <summary>
    /// The version byte used for encoded NATS Seeds.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'S...'</remarks>
    public const byte PrefixByteSeed = 18 << 3;

    /// <summary>
    /// The version byte used for encoded NATS Private keys.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'P...'</remarks>
    public const byte PrefixBytePrivate = 15 << 3;

    /// <summary>
    /// The version byte used for encoded NATS Servers.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'N...'</remarks>
    public const byte PrefixByteServer = 13 << 3;

    /// <summary>
    /// The version byte used for encoded NATS Clusters.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'C...'</remarks>
    public const byte PrefixByteCluster = 2 << 3;

    /// <summary>
    /// The version byte used for encoded NATS Operators.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'O...'</remarks>
    public const byte PrefixByteOperator = 14 << 3;

    /// <summary>
    /// The version byte used for encoded NATS Accounts.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'A...'</remarks>
    public const byte PrefixByteAccount = 0;

    /// <summary>
    /// The version byte used for encoded NATS Users.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'U...'</remarks>
    public const byte PrefixByteUser = 20 << 3;

    /// <summary>
    /// The version byte used for Curve Keys (X25519).
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'X...'</remarks>
    public const byte PrefixByteCurve = 23 << 3;

    /// <summary>
    /// The version byte used for unknown prefixes.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'Z...'</remarks>
    public const byte PrefixByteUnknown = 25 << 3;
}
