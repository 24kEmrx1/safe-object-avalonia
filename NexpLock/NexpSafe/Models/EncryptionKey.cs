namespace NexpSafe.Models;

public sealed record EncryptionKey(string FileId, string EncryptedFilePrivateKey, byte[] KeyHash);