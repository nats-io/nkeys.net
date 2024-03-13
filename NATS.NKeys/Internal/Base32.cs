using System;

namespace NATS.NKeys.Internal
{
    // Borrowed from:  https://stackoverflow.com/a/7135008
    internal static class Base32
    {
        public static byte[] Decode(string input)
        {
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException(nameof(input));
            }

            input = input.TrimEnd('='); //remove padding characters

            var byteCount = input.Length * 5 / 8; // this must be TRUNCATED
            var returnArray = new byte[byteCount];

            byte curByte = 0, bitsRemaining = 8;
            int mask = 0, arrayIndex = 0;

            for (var index = 0; index < input.Length; index++)
            {
                var c = input[index];
                var cValue = CharToValue(c);

                if (bitsRemaining > 5)
                {
                    mask = cValue << (bitsRemaining - 5);
                    curByte = (byte)(curByte | mask);
                    bitsRemaining -= 5;
                }
                else
                {
                    mask = cValue >> (5 - bitsRemaining);
                    curByte = (byte)(curByte | mask);
                    returnArray[arrayIndex++] = curByte;
                    curByte = (byte)(cValue << (3 + bitsRemaining));
                    bitsRemaining += 3;
                }
            }

            // if we didn't end with a full byte
            if (arrayIndex != byteCount)
            {
                returnArray[arrayIndex] = curByte;
            }

            return returnArray;
        }

        public static string Encode(byte[] input)
        {
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException("input");
            }

            var charCount = (int)Math.Ceiling(input.Length / 5d) * 8;
            var returnArray = new char[charCount];

            byte nextChar = 0, bitsRemaining = 5;
            var arrayIndex = 0;

            foreach (var b in input)
            {
                nextChar = (byte)(nextChar | (b >> (8 - bitsRemaining)));
                returnArray[arrayIndex++] = ValueToChar(nextChar);

                if (bitsRemaining < 4)
                {
                    nextChar = (byte)((b >> (3 - bitsRemaining)) & 31);
                    returnArray[arrayIndex++] = ValueToChar(nextChar);
                    bitsRemaining += 5;
                }

                bitsRemaining -= 3;
                nextChar = (byte)((b << bitsRemaining) & 31);
            }

            // if we didn't end with a full char
            if (arrayIndex < charCount)
            {
                returnArray[arrayIndex++] = ValueToChar(nextChar);

                // NOTE: Base32 padding omitted
            }

            return new string(returnArray, 0, arrayIndex);
        }

        private static int CharToValue(char c)
        {
            var value = (int)c;

            // 65-90 == uppercase letters
            if (value < 91 && value > 64)
                return value - 65;

            // 50-55 == numbers 2-7
            if (value < 56 && value > 49)
                return value - 24;

            // 97-122 == lowercase letters
            if (value < 123 && value > 96)
                return value - 97;

            throw new ArgumentException("Character is not a Base32 character.", "c");
        }

        private static char ValueToChar(byte b)
        {
            if (b < 26)
                return (char)(b + 65);
            if (b < 32)
                return (char)(b + 24);
            throw new ArgumentException("Byte is not a value Base32 value.", "b");
        }
        
        private const int InByteSize = 8;

        /// <summary>
        /// Size of converted byte in bits
        /// </summary>
        private const int OutByteSize = 5;
        private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        public static byte[] FromBase32String(string base32String)
        {
            // Check if string is null
            if (base32String == null)
            {
                return null;
            }
            // Check if empty
            else if (base32String == string.Empty)
            {
                return new byte[0];
            }

            // Convert to upper-case
            string base32StringUpperCase = base32String.ToUpperInvariant();

            // Prepare output byte array
            byte[] outputBytes = new byte[base32StringUpperCase.Length * OutByteSize / InByteSize];

            // Check the size
            if (outputBytes.Length == 0)
            {
                throw new ArgumentException("Specified string is not valid Base32 format because it doesn''t have enough data to construct a complete byte array");
            }

            // Position in the string
            int base32Position = 0;

            // Offset inside the character in the string
            int base32SubPosition = 0;

            // Position within outputBytes array
            int outputBytePosition = 0;

            // The number of bits filled in the current output byte
            int outputByteSubPosition = 0;

            // Normally we would iterate on the input array but in this case we actually iterate on the output array
            // We do it because output array doesn''t have overflow bits, while input does and it will cause output array overflow if we don''t stop in time
            while (outputBytePosition < outputBytes.Length)
            {
                // Look up current character in the dictionary to convert it to byte
                int currentBase32Byte = Base32Alphabet.IndexOf(base32StringUpperCase[base32Position]);

                // Check if found
                if (currentBase32Byte < 0)
                {
                    throw new ArgumentException(string.Format("Specified string is not valid Base32 format because character \"{0}\" does not exist in Base32 alphabet", base32String[base32Position]));
                }

                // Calculate the number of bits we can extract out of current input character to fill missing bits in the output byte
                int bitsAvailableInByte = Math.Min(OutByteSize - base32SubPosition, InByteSize - outputByteSubPosition);

                // Make space in the output byte
                outputBytes[outputBytePosition] <<= bitsAvailableInByte;

                // Extract the part of the input character and move it to the output byte
                outputBytes[outputBytePosition] |= (byte)(currentBase32Byte >> (OutByteSize - (base32SubPosition + bitsAvailableInByte)));

                // Update current sub-byte position
                outputByteSubPosition += bitsAvailableInByte;

                // Check overflow
                if (outputByteSubPosition >= InByteSize)
                {
                    // Move to the next byte
                    outputBytePosition++;
                    outputByteSubPosition = 0;
                }

                // Update current base32 byte completion
                base32SubPosition += bitsAvailableInByte;

                // Check overflow or end of input array
                if (base32SubPosition >= OutByteSize)
                {
                    // Move to the next character
                    base32Position++;
                    base32SubPosition = 0;
                }
            }

            return outputBytes;
        }    
    }
}