using System;

namespace NATS.NKeys
{
    /// <summary>
    /// Represents an exception specific to the NKeys library.
    /// </summary>
    public class NKeysException(string message) : Exception(message);
}
