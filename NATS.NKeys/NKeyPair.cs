using System;
using System.Diagnostics.CodeAnalysis;
using NATS.NKeys.NaCl;

namespace NATS.NKeys
{
    /// <summary>
    /// Partial implementation of the NATS Ed25519 KeyPair.  This is not complete, but provides enough
    /// functionality to implement the client side NATS 2.0 security scheme.
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.OrderingRules", "SA1201:Elements should appear in the correct order", Justification = "Legacy code")]
    public sealed class NKeyPair : IDisposable
    {
        private byte[] _seed;
        private byte[] _expandedPrivateKey;
        private byte[] _key;

        public NKeys.PrefixType Type { get; }

        internal NKeyPair(byte[] publicKey, byte[] privateKey, NKeys.PrefixType type)
        {
            _key = publicKey;
            _expandedPrivateKey = privateKey;
            _seed = [];
            Type = type;
        }

        internal NKeyPair(byte[] userSeed, NKeys.PrefixType type)
        {
            if (userSeed == null)
            {
                throw new NKeysException("seed cannot be null");
            }

            var len = userSeed.Length;
            if (len != Ed25519.PrivateKeySeedSize)
            {
                throw new NKeysException("invalid seed length");
            }

            _seed = new byte[len];
            Buffer.BlockCopy(userSeed, 0, _seed, 0, len);
            Ed25519.KeyPairFromSeed(out _key, out _expandedPrivateKey, _seed);
            Type = type;
        }

        /// <summary>
        /// Gets the public key of the keypair.
        /// </summary>
        public byte[] PublicKey => _key;

        public string EncodedPublicKey => NKeys.Encode(NKeys.PrefixFromType(Type), false, _key);

        /// <summary>
        /// Gets the private key of the keypair.
        /// </summary>
        public byte[] PrivateKeySeed => _seed;

        public string EncodedSeed => NKeys.Encode(NKeys.PrefixFromType(Type), true, _seed);

        /// <summary>
        /// Wipes clean the internal private keys.
        /// </summary>
        public void Wipe()
        {
            NKeys.Wipe(ref _seed);
            NKeys.Wipe(ref _expandedPrivateKey);
            NKeys.Wipe(ref _key);
        }

        /// <summary>
        /// Signs data and returns a signature.
        /// </summary>
        /// <param name="src"></param>
        /// <returns>The signature.</returns>
        public byte[] Sign(byte[] src)
        {
            var rv = Ed25519.Sign(src, _expandedPrivateKey);
            CryptoBytes.Wipe(_expandedPrivateKey);
            return rv;
        }

        public bool Verify(byte[] signature, byte[] message) =>
            Ed25519.Verify(signature, message, _key);

        /// <summary>
        /// Releases all resources used by the NkeyPair.
        /// </summary>
        public void Dispose() => Dispose(true);

        private bool _disposedValue; // To detect redundant calls

        /// <summary>
        /// Releases the unmanaged resources used by the NkeyPair and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        private void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    Wipe();
                }

                _disposedValue = true;
            }
        }
    }
}
