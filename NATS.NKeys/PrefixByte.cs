namespace NATS.NKeys;

public enum PrefixByte : byte
{
    Operator = NKeysConstants.PrefixByteOperator,
    Server = NKeysConstants.PrefixByteServer,
    Cluster = NKeysConstants.PrefixByteCluster,
    Account = NKeysConstants.PrefixByteAccount,
    User = NKeysConstants.PrefixByteUser,
}
