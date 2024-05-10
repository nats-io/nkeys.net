using System;
using NATS.NKeys.NaCl;

namespace NATS.NKeys
{
    /// <summary>
    /// Partial implementation of the NATS Ed25519 KeyPair.  This is not complete, but provides enough
    /// functionality to implement the client side NATS 2.0 security scheme.
    /// </summary>
    public sealed class NKeyPair : IDisposable
    {
        private byte[] seed;
        private byte[] expandedPrivateKey;
        private byte[] key;
        public NKeys.PrefixType Type { get; }

        internal NKeyPair(byte[] publicKey, byte[] privateKey, NKeys.PrefixType type) {
            this.key = publicKey;
            this.expandedPrivateKey = privateKey;
            this.Type = type;
        }

        internal NKeyPair(byte[] userSeed, NKeys.PrefixType type)
        {
            if (userSeed == null)
            {
                throw new NKeysException("seed cannot be null");
            }

            int len = userSeed.Length;
            if (len != Ed25519.PrivateKeySeedSize)
            {
                throw new NKeysException("invalid seed length");
            }

            seed = new byte[len];
            Buffer.BlockCopy(userSeed, 0, seed, 0, len);
            Ed25519.KeyPairFromSeed(out key, out expandedPrivateKey, seed);
            Type = type;
        }

        /// <summary>
        /// Gets the public key of the keypair.
        /// </summary>
        public byte[] PublicKey => key;

        public string EncodedPublicKey => NKeys.Encode(NKeys.PrefixFromType(Type), false, key);

        /// <summary>
        /// Gets the private key of the keypair.
        /// </summary>
        public byte[] PrivateKeySeed => seed;

        public string EncodedSeed => NKeys.Encode(NKeys.PrefixFromType(Type), true, seed);
        
        /// <summary>
        /// Wipes clean the internal private keys.
        /// </summary>
        public void Wipe()
        {
            NKeys.Wipe(ref seed);
            NKeys.Wipe(ref expandedPrivateKey);
        }

        /// <summary>
        /// Signs data and returns a signature.
        /// </summary>
        /// <param name="src"></param>
        /// <returns>The signature.</returns>
        public byte[] Sign(byte[] src)
        {
            byte[] rv =  Ed25519.Sign(src, expandedPrivateKey);
            CryptoBytes.Wipe(expandedPrivateKey);
            return rv;
        }
        
        public bool Verify(byte[] signature, byte[] message)
        {
            return Ed25519.Verify(signature, message, key);
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        /// <summary>
        /// Releases the unmanaged resources used by the NkeyPair and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    Wipe();
                }
                key = null;
                disposedValue = true;
            }
        }

        /// <summary>
        /// Releases all resources used by the NkeyPair.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}