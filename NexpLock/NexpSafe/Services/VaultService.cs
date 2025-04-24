using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using NexpSafe.Interfaces;
using NexpSafe.Models;

namespace NexpSafe.Services;

public sealed class VaultService : IVaultService, IDisposable
{
    private readonly ILogger<VaultService> _logger;
    private readonly string _spStorageFile;
    private readonly string _storagePath;
    private volatile bool _disposed;

    public VaultService(ILogger<VaultService> logger, string? storagePath = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        var baseDirectory = Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) ??
                            AppDomain.CurrentDomain.BaseDirectory;

        _storagePath = storagePath ?? Path.Combine(baseDirectory, Constants.Security.KeyVault.StoragePath);
        _spStorageFile = Path.Combine(_storagePath, Constants.Security.KeyVault.SpBin);

        Task.Run(InitializeStorageAsync);
    }

    public async Task<string> StoreKeyAsync(string fileId, string filePrivateKey, string filePublicMasterKey,
        byte[] fileHash, string destinationFilePath)
    {
        EnsureNotDisposed();

        var dataToEncrypt = $"{filePrivateKey}|{Convert.ToBase64String(fileHash)}";
        var encryptedPrivateKey = await EncryptWithKeyAsync(dataToEncrypt, filePublicMasterKey);
        var finalEncryptedKey = await EncryptWithSystemKeyAsync(encryptedPrivateKey);

        var keyHash = ComputeKeyHash(finalEncryptedKey);
        var encryptionKey = new EncryptionKey(fileId, finalEncryptedKey, keyHash);

        await PersistKeyAsync(encryptionKey, filePublicMasterKey, destinationFilePath);
        return finalEncryptedKey;
    }

    public async Task<(string filePrivateKey, byte[] fileHash)> RetrieveKeyAsync(string fileId,
        string filePublicMasterKey, string sourceFilePath)
    {
        EnsureNotDisposed();

        var encryptionKey = await LoadKeyAsync(fileId, filePublicMasterKey, sourceFilePath);
        if (encryptionKey is null)
            throw new KeyNotFoundException($"No key found for file ID: {fileId}");

        VerifyKeyIntegrity(encryptionKey);
        var decryptedKeyLayerOne = await DecryptWithSystemKeyAsync(encryptionKey.EncryptedFilePrivateKey);
        var decryptedData = await DecryptWithKeyAsync(decryptedKeyLayerOne, filePublicMasterKey);
        var parts = decryptedData.Split('|', 2);
        if (parts.Length is not 2)
            throw new InvalidDataException("Invalid key data format.");

        var filePrivateKey = parts[0];
        var fileHash = Convert.FromBase64String(parts[1]);
        return (filePrivateKey, fileHash);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private async Task InitializeStorageAsync()
    {
        Directory.CreateDirectory(_storagePath);
        var flushFilePath = Path.Combine(_storagePath, $"flush_{Guid.NewGuid():N}.tmp");
        await using (var stream = new DirectStream(
                         flushFilePath,
                         FileMode.Create,
                         FileAccess.Write,
                         FileShare.None,
                         Constants.Storage.BufferSize,
                         FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough,
                         null))
        {
            await stream.FlushAsync();
        }

        File.Delete(flushFilePath);

        await InitializeOrGetSystemKey(_spStorageFile);
    }

    ~VaultService()
    {
        Dispose();
    }

    private Task<string> EncryptAsync(string data, byte[] key)
    {
        EnsureNotDisposed();

        var nonce = GenerateNonce();
        var plaintext = Encoding.UTF8.GetBytes(data);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[Constants.Security.KeyVault.TagSize];

        using (var aesGcm = new AesGcm(key, Constants.Security.KeyVault.TagSize))
        {
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        var output = CombineEncryptionComponents(nonce, ciphertext, tag);
        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(ciphertext);
        return Task.FromResult(output);
    }

    private Task<string> DecryptAsync(string encryptedData, byte[] key)
    {
        EnsureNotDisposed();

        var (nonce, ciphertext, tag) = ExtractEncryptionComponents(encryptedData);
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using (var aesGcm = new AesGcm(key, Constants.Security.KeyVault.TagSize))
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            return Task.FromResult(Encoding.UTF8.GetString(plaintext));
        }
        catch (CryptographicException ex)
        {
            _logger.LogError("Decryption failed: {Error}", ex.Message);
            throw new InvalidDataException("Decryption failed: Data corrupted or invalid key.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private byte[] InitializeSystemKey(int keySize)
    {
        if (keySize is not (128 or 192 or 256))
            throw new ArgumentOutOfRangeException(nameof(keySize), "Key size must be 128, 192, or 256 bits.");

        if (File.Exists(_spStorageFile))
        {
            var key = File.ReadAllBytes(_spStorageFile);
            if (key.Length == keySize / 8) return key;
        }

        var keyBytes = new byte[keySize / 8];
        RandomNumberGenerator.Fill(keyBytes);

        using var keyDerivation = new Rfc2898DeriveBytes(
            keyBytes,
            RandomNumberGenerator.GetBytes(Constants.Security.KeyVault.SaltSize),
            Constants.Security.KeyVault.Iterations,
            Constants.Security.KeyVault.HashAlgorithm
        );

        var derivedKey = keyDerivation.GetBytes(keySize / 8);
        CryptographicOperations.ZeroMemory(keyBytes);
        return derivedKey;
    }

    private async Task InitializeOrGetSystemKey(string filePath)
    {
        if (File.Exists(filePath))
            return;

        var key = InitializeSystemKey(Constants.Security.KeyVault.KeySize);
        await File.WriteAllBytesAsync(filePath, key);

        CryptographicOperations.ZeroMemory(key);
    }

    private byte[] GetSystemSecurityKey()
    {
        if (File.Exists(_spStorageFile) is not true)
            throw new FileNotFoundException("System security key file not found.", _spStorageFile);
        return File.ReadAllBytes(_spStorageFile);
    }

    private Task<string> EncryptWithKeyAsync(string data, string key)
    {
        return EncryptAsync(data, Convert.FromBase64String(key));
    }

    private Task<string> EncryptWithSystemKeyAsync(string data)
    {
        var systemKey = GetSystemSecurityKey();
        return EncryptAsync(data, systemKey);
    }

    private Task<string> DecryptWithKeyAsync(string encryptedData, string key)
    {
        return DecryptAsync(encryptedData, Convert.FromBase64String(key));
    }

    private Task<string> DecryptWithSystemKeyAsync(string encryptedData)
    {
        var systemKey = GetSystemSecurityKey();
        return DecryptAsync(encryptedData, systemKey);
    }

    private static byte[] ComputeKeyHash(string encryptedKey)
    {
        return SHA256.HashData(Convert.FromBase64String(encryptedKey));
    }

    private static void VerifyKeyIntegrity(EncryptionKey encryptionKey)
    {
        var currentHash = ComputeKeyHash(encryptionKey.EncryptedFilePrivateKey);
        if (currentHash.SequenceEqual(encryptionKey.KeyHash))
            return;

        throw new InvalidDataException("Stored key is corrupted.");
    }

    private async Task PersistKeyAsync(EncryptionKey key, string publicMasterKey, string destinationFilePath)
    {
        EnsureNotDisposed();

        var keyData = $"{key.EncryptedFilePrivateKey}|{Convert.ToBase64String(key.KeyHash)}";
        var encryptedKeyData = await EncryptWithKeyAsync(keyData, publicMasterKey);
        var encryptedKeyDataBytes = Encoding.UTF8.GetBytes(encryptedKeyData);
        var keyDataLength = encryptedKeyDataBytes.Length;
        var lengthBytes = BitConverter.GetBytes(keyDataLength);

        await using var stream = new DirectStream(
            destinationFilePath,
            FileMode.Append,
            FileAccess.Write,
            FileShare.None,
            Constants.Storage.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough,
            null);

        await stream.WriteAsync(encryptedKeyDataBytes.AsMemory(), CancellationToken.None);
        await stream.WriteAsync(lengthBytes.AsMemory(), CancellationToken.None);
        await stream.FlushAsync();
    }

    private async Task<EncryptionKey?> LoadKeyAsync(string fileId, string filePublicMasterKey, string sourceFilePath)
    {
        EnsureNotDisposed();

        await using var stream = new DirectStream(
            sourceFilePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None,
            Constants.Storage.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan,
            null);

        if (stream.Length < 4)
            throw new InvalidDataException("File is too short to contain key data.");

        stream.Seek(-4, SeekOrigin.End);

        var lengthBytes = new byte[4];
        await stream.ReadExactlyAsync(lengthBytes, 0, 4);

        var keyDataLength = BitConverter.ToInt32(lengthBytes);
        if (keyDataLength <= 0 || stream.Length < keyDataLength + 4)
            throw new InvalidDataException("Invalid key data length in file.");

        stream.Seek(-(keyDataLength + 4), SeekOrigin.End);

        var encryptedKeyDataBytes = new byte[keyDataLength];
        await stream.ReadExactlyAsync(encryptedKeyDataBytes, 0, keyDataLength);

        var encryptedDataString = Encoding.UTF8.GetString(encryptedKeyDataBytes);
        CryptographicOperations.ZeroMemory(encryptedKeyDataBytes);

        try
        {
            var decryptedData = await DecryptWithKeyAsync(encryptedDataString, filePublicMasterKey);
            var parts = decryptedData.Split('|');
            if (parts.Length is not 2)
                return null;

            var encryptedKey = parts[0];
            var keyHash = Convert.FromBase64String(parts[1]);

            return new EncryptionKey(fileId, encryptedKey, keyHash);
        }
        catch (CryptographicException ex)
        {
            _logger.LogError("Failed to decrypt key data: {Error}", ex.Message);
            return null;
        }
    }

    private static byte[] GenerateNonce()
    {
        var nonce = new byte[Constants.Security.KeyVault.NonceSize];
        RandomNumberGenerator.Fill(nonce);
        return nonce;
    }

    private static string CombineEncryptionComponents(byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        var result = new byte[Constants.Security.KeyVault.NonceSize + ciphertext.Length +
                              Constants.Security.KeyVault.TagSize];

        Buffer.BlockCopy(nonce, 0, result, 0, Constants.Security.KeyVault.NonceSize);
        Buffer.BlockCopy(ciphertext, 0, result, Constants.Security.KeyVault.NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, Constants.Security.KeyVault.NonceSize + ciphertext.Length,
            Constants.Security.KeyVault.TagSize);

        var output = Convert.ToBase64String(result);
        CryptographicOperations.ZeroMemory(result);

        return output;
    }

    private static (byte[] nonce, byte[] ciphertext, byte[] tag) ExtractEncryptionComponents(string encryptedData)
    {
        var fullData = Convert.FromBase64String(encryptedData);

        if (fullData.Length < Constants.Security.KeyVault.NonceSize + Constants.Security.KeyVault.TagSize)
            throw new ArgumentException("Encrypted data is invalid or corrupted");

        var nonce = new byte[Constants.Security.KeyVault.NonceSize];
        Buffer.BlockCopy(fullData, 0, nonce, 0, Constants.Security.KeyVault.NonceSize);

        var ciphertextLength = fullData.Length - Constants.Security.KeyVault.NonceSize -
                               Constants.Security.KeyVault.TagSize;
        var ciphertext = new byte[ciphertextLength];
        Buffer.BlockCopy(fullData, Constants.Security.KeyVault.NonceSize, ciphertext, 0, ciphertextLength);

        var tag = new byte[Constants.Security.KeyVault.TagSize];
        Buffer.BlockCopy(fullData, fullData.Length - Constants.Security.KeyVault.TagSize, tag, 0,
            Constants.Security.KeyVault.TagSize);

        return (nonce, ciphertext, tag);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void EnsureNotDisposed()
    {
        if (_disposed is not true)
            return;
        throw new ObjectDisposedException(nameof(VaultService));
    }
}