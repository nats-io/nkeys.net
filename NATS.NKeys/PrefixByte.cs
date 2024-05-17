using NATS.NKeys.Internal;

namespace NATS.NKeys;

/// <summary>
/// Lists the prefix bytes used in the NATS NKeys library.
/// </summary>
public enum PrefixByte : byte
{
    /// <summary>
    /// The version byte used for encoded NATS Operators.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'O...'</remarks>
    Operator = NKeysConstants.PrefixByteOperator,

    /// <summary>
    /// The version byte used for encoded NATS Servers.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'N...'</remarks>
    Server = NKeysConstants.PrefixByteServer,

    /// <summary>
    /// The version byte used for encoded NATS Clusters.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'C...'</remarks>
    Cluster = NKeysConstants.PrefixByteCluster,

    /// <summary>
    /// The version byte used for encoded NATS Accounts.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'A...'</remarks>
    Account = NKeysConstants.PrefixByteAccount,

    /// <summary>
    /// The version byte used for encoded NATS Users.
    /// </summary>
    /// <remarks>When encoded as base32, it encodes to 'U...'</remarks>
    User = NKeysConstants.PrefixByteUser,
}
