using System.Security.Cryptography;

namespace NexpSafe;

public static class Constants
{
    public static class Storage
    {
        public const int BufferSize = 81920;
    }

    public static class Security
    {
        public static class KeyVault
        {
            public const int Iterations = 600 * 1000;
            public const int KeySize = 256;
            public const int SaltSize = 64;
            public const int NonceSize = 12;
            public const int TagSize = 16;

            public const string StoragePath = "lockedbox";
            public const string SpBin = "sp_80038b.bin";

            public static readonly HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA3_512;
        }
    }

    public static class Linux
    {
        public static class FileAdvice
        {
            public const int DontNeed = 4;
            public const int Sequential = 2;
        }

        public static class IoPriority
        {
            public const int WhoProcess = 1;
            public const int ClassRealTime = 1;
            public const int ClassBestEffort = 2;
            public const int ClassShift = 13;
            public const long SysSet = 251;
        }
    }

    public static class DirectStream
    {
        public static class SpinWait
        {
            public const int MinDuration = 10;
            public const int MaxDuration = 50;
        }
    }
}