using System;

namespace NATS.NKeys
{
    internal class NKeysException : Exception
    {
        public NKeysException(string message)
            : base(message)
        {
        }
    }
}
