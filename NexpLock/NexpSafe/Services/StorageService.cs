using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using NexpSafe.Interfaces;
using NexpSafe.Models;

namespace NexpSafe.Services;

public sealed class StorageService(
    IVaultService keyVaultService,
    ILogger<StorageService> logger)
    : IStorageService, IDisposable
{
    private readonly IVaultService? _keyVaultService = keyVaultService;
    private bool _disposed;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public async Task EncryptFileAsync(FileProcessingRequest request, string filePublicMasterKey,
        CancellationToken cancellationToken, IProgress<(double percentage, string message)> progress)
    {
        ThrowIfDisposed();
        ValidateSecurityOperation();

        LogDebugInfo(request.FileId, filePublicMasterKey);

        progress.Report((0, "Starting encryption..."));

        var filePrivateKey = Convert.ToBase64String(GenerateRandomKey());
        var key = Convert.FromBase64String(filePrivateKey);
        var nonce = new byte[Constants.Security.KeyVault.NonceSize];
        RandomNumberGenerator.Fill(nonce);

        try
        {
            progress.Report((5, "Processing file..."));
            var fileHash = await ProcessEncryptionStreamAsync(request, key, nonce, cancellationToken, progress);
            progress.Report((95, "Storing encryption key and hash..."));
            await _keyVaultService!.StoreKeyAsync(request.FileId, filePrivateKey, filePublicMasterKey,
                fileHash, request.DestinationPath);
            progress.Report((100, "Encryption completed"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public async Task DecryptFileAsync(FileProcessingRequest request, string filePublicMasterKey,
        CancellationToken cancellationToken, IProgress<(double percentage, string message)> progress)
    {
        ThrowIfDisposed();
        ValidateSecurityOperation();

        LogDebugInfo(request.FileId, filePublicMasterKey);
        progress.Report((0, "Starting decryption..."));

        var (filePrivateKey, storedFileHash) =
            await _keyVaultService!.RetrieveKeyAsync(request.FileId, filePublicMasterKey, request.SourcePath);
        progress.Report((5, "Retrieved encryption key and hash..."));
        var key = Convert.FromBase64String(filePrivateKey);

        try
        {
            await using var sourceStream = CreateFileStream(request.SourcePath, FileMode.Open, FileAccess.Read, logger);
            await using var destinationStream =
                CreateFileStream(request.DestinationPath, FileMode.Create, FileAccess.Write, logger);

            progress.Report((10, "Processing file..."));
            var computedHash =
                await ProcessDecryptionAsync(key, sourceStream, destinationStream, cancellationToken, progress);
            if (computedHash.SequenceEqual(storedFileHash) is not true)
                throw new InvalidDataException("File integrity check failed: Data corrupted.");
            progress.Report((100, "Decryption completed"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
            if (_keyVaultService is IDisposable vaultService)
                vaultService.Dispose();

        _disposed = true;
    }

    ~StorageService()
    {
        Dispose(false);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ThrowIfDisposed()
    {
        if (_disposed is not true) return;

        throw new ObjectDisposedException(nameof(StorageService));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateSecurityOperation()
    {
        if (SecurityService.ValidateOperation() is not true)
        {
            SecurityService.ProcessPaddingBuffer();
            throw new SecurityException("Security validation failed");
        }

        Thread.MemoryBarrier();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static DirectStream CreateFileStream(string path, FileMode mode, FileAccess access,
        ILogger<StorageService>? logger)
    {
        ValidateSecurityOperation();

        return new DirectStream(path, mode, access, FileShare.None, Constants.Storage.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan |
            (access is FileAccess.Write ? FileOptions.WriteThrough : FileOptions.None), logger);
    }
    
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DeriveNonce(byte[] originalNonce, long blockIndex, byte[] outputNonce)
    {
        if (originalNonce is null || outputNonce is null)
            throw new ArgumentNullException(originalNonce is null ? nameof(originalNonce) : nameof(outputNonce));

        if (outputNonce.Length < Constants.Security.KeyVault.NonceSize)
            throw new ArgumentException(
                $"Output nonce buffer must be at least {Constants.Security.KeyVault.NonceSize} bytes");

        try
        {
            Span<byte> blockIndexBytes = stackalloc byte[sizeof(long)];
            if (BitConverter.TryWriteBytes(blockIndexBytes, blockIndex) is not true)
                throw new InvalidOperationException("Failed to convert block index to bytes");

            Span<byte> salt = stackalloc byte[32];
            originalNonce.AsSpan(0, Math.Min(originalNonce.Length, Constants.Security.KeyVault.NonceSize)).CopyTo(salt);

            for (var i = Constants.Security.KeyVault.NonceSize; i < salt.Length; i++)
                salt[i] = (byte)(0xAA ^ (i & 0xFF));

            Span<byte> prk = stackalloc byte[32];
            {
                using var hmac = new HMACSHA256();
                hmac.Key = salt.ToArray(); 
                
                if (!hmac.TryComputeHash(blockIndexBytes, prk, out var bytesWritten) || bytesWritten is not 32)
                    throw new CryptographicException("HMAC computation failed during HKDF-Extract");
                
                CryptographicOperations.ZeroMemory(hmac.Key);
            }

            Span<byte> info = stackalloc byte[sizeof(long) + 16];
            blockIndexBytes.CopyTo(info);
            var context = "AES-GCM-NONCE-V1"u8;
            context.CopyTo(info[sizeof(long)..]);

            Span<byte> okm = stackalloc byte[Constants.Security.KeyVault.NonceSize];
            Span<byte> t = stackalloc byte[32];
            Span<byte> input = stackalloc byte[32 + info.Length + 1];
            Span<byte> currentT = stackalloc byte[32];
            var tPos = 0;
            byte counter = 1;

            using (var hmacExpand = new HMACSHA256())
            {
                hmacExpand.Key = prk.ToArray(); 

                var bytesToProcess = okm.Length;
                var okmPos = 0;

                while (bytesToProcess > 0)
                {
                    input.Clear();
                    if (tPos > 0)
                        t[..tPos].CopyTo(input);

                    info.CopyTo(input[tPos..]);
                    input[tPos + info.Length] = counter++;

                    currentT.Clear();
                    if (!hmacExpand.TryComputeHash(input[..(tPos + info.Length + 1)], currentT, out var bytesWritten) ||
                        bytesWritten is not 32)
                        throw new CryptographicException("HMAC computation failed during HKDF-Expand");

                    var bytesToCopy = Math.Min(bytesToProcess, currentT.Length);
                    currentT[..bytesToCopy].CopyTo(okm[okmPos..]);
                    okmPos += bytesToCopy;
                    bytesToProcess -= bytesToCopy;
                    currentT.CopyTo(t);
                    tPos = currentT.Length;
                }
                
                CryptographicOperations.ZeroMemory(hmacExpand.Key);
            }
            
            okm.CopyTo(outputNonce.AsSpan(0, Constants.Security.KeyVault.NonceSize));
            
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(okm);
            CryptographicOperations.ZeroMemory(t);
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(currentT);
            CryptographicOperations.ZeroMemory(info);
            CryptographicOperations.ZeroMemory(blockIndexBytes);
        }
        catch (Exception ex)
        {
            throw new CryptographicException("Nonce derivation failed", ex);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private async Task<byte[]> ProcessEncryptionStreamAsync(FileProcessingRequest request, byte[] key, byte[] nonce,
        CancellationToken cancellationToken, IProgress<(double percentage, string message)> progress)
    {
        ValidateSecurityOperation();

        await using var sourceStream = new DirectStream(
            request.SourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            Constants.Storage.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan,
            logger);

        await using var destinationStream = new DirectStream(
            request.DestinationPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            Constants.Storage.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan,
            logger);

        await destinationStream.WriteAsync(nonce.AsMemory(), cancellationToken);
        await destinationStream.FlushAsync(cancellationToken);

        using var aesGcm = new AesGcm(key, Constants.Security.KeyVault.TagSize);
        using var hashAlgorithm = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var fileLength = sourceStream.Length;
        var totalBlocks = (long)Math.Ceiling((double)fileLength / Constants.Storage.BufferSize);

        var buffer = ArrayPool<byte>.Shared.Rent(Constants.Storage.BufferSize);
        var ciphertext = ArrayPool<byte>.Shared.Rent(Constants.Storage.BufferSize);
        var tag = ArrayPool<byte>.Shared.Rent(Constants.Security.KeyVault.TagSize);
        var chunkNonce = ArrayPool<byte>.Shared.Rent(Constants.Security.KeyVault.NonceSize);
        var combinedBuffer =
            ArrayPool<byte>.Shared.Rent(Constants.Security.KeyVault.TagSize + Constants.Storage.BufferSize);

        try
        {
            for (long blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
            {
                var bytesRead = await sourceStream.ReadAsync(
                    buffer.AsMemory(0, Constants.Storage.BufferSize),
                    cancellationToken);

                if (bytesRead is 0) break;

                hashAlgorithm.AppendData(buffer, 0, bytesRead);

                var progressPercentage = 10 + (blockIndex + 1) * 90 / totalBlocks;
                progress.Report((progressPercentage, $"Processing block {blockIndex + 1} of {totalBlocks}..."));

                DeriveNonce(nonce, blockIndex, chunkNonce);

                aesGcm.Encrypt(
                    chunkNonce.AsSpan(0, Constants.Security.KeyVault.NonceSize),
                    buffer.AsSpan(0, bytesRead),
                    ciphertext.AsSpan(0, bytesRead),
                    tag.AsSpan(0, Constants.Security.KeyVault.TagSize));

                var combinedSpan = combinedBuffer.AsSpan();
                tag.AsSpan().CopyTo(combinedSpan);
                ciphertext.AsSpan(0, bytesRead).CopyTo(combinedSpan[Constants.Security.KeyVault.TagSize..]);

                await destinationStream.WriteAsync(
                    combinedBuffer.AsMemory(0, Constants.Security.KeyVault.TagSize + bytesRead),
                    cancellationToken);
                await destinationStream.FlushAsync(cancellationToken);
            }

            return hashAlgorithm.GetCurrentHash();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, true);
            ArrayPool<byte>.Shared.Return(ciphertext, true);
            ArrayPool<byte>.Shared.Return(tag, true);
            ArrayPool<byte>.Shared.Return(chunkNonce, true);
            ArrayPool<byte>.Shared.Return(combinedBuffer, true);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private async Task<byte[]> ProcessDecryptionAsync(byte[] key, Stream sourceStream, Stream destinationStream,
        CancellationToken cancellationToken, IProgress<(double percentage, string message)> progress)
    {
        ValidateSecurityOperation();

        sourceStream.Seek(-4, SeekOrigin.End);
        var lengthBytes = new byte[4];
        await sourceStream.ReadExactlyAsync(lengthBytes, 0, 4, cancellationToken);
        var keyDataLength = BitConverter.ToInt32(lengthBytes);

        var encryptedDataLength = sourceStream.Length - keyDataLength - 4;
        if (encryptedDataLength < Constants.Security.KeyVault.NonceSize)
            throw new InvalidDataException("File is too short to contain encrypted data.");

        sourceStream.Seek(0, SeekOrigin.Begin);

        var nonce = ArrayPool<byte>.Shared.Rent(Constants.Security.KeyVault.NonceSize);
        try
        {
            await sourceStream.ReadExactlyAsync(nonce.AsMemory(0, Constants.Security.KeyVault.NonceSize),
                cancellationToken);
            using var aesGcm = new AesGcm(key, Constants.Security.KeyVault.TagSize);
            using var hashAlgorithm = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            var tag = ArrayPool<byte>.Shared.Rent(Constants.Security.KeyVault.TagSize);
            var buffer = ArrayPool<byte>.Shared.Rent(Constants.Storage.BufferSize);
            var plaintext = ArrayPool<byte>.Shared.Rent(Constants.Storage.BufferSize);
            var chunkNonce = ArrayPool<byte>.Shared.Rent(Constants.Security.KeyVault.NonceSize);

            try
            {
                var totalLength = encryptedDataLength - Constants.Security.KeyVault.NonceSize;
                var totalBlocks = (long)Math.Ceiling((double)totalLength /
                                                     (Constants.Storage.BufferSize +
                                                      Constants.Security.KeyVault.TagSize));

                for (long blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
                {
                    var remainingBytes = encryptedDataLength - sourceStream.Position;
                    if (remainingBytes < Constants.Security.KeyVault.TagSize)
                        break;

                    var tagRead = await sourceStream.ReadAsync(
                        tag.AsMemory(0, Constants.Security.KeyVault.TagSize),
                        cancellationToken);

                    if (tagRead is not Constants.Security.KeyVault.TagSize)
                        throw new InvalidDataException("Failed to read tag data.");

                    var maxBufferSize = Math.Min(remainingBytes - tagRead, Constants.Storage.BufferSize);
                    var bytesRead = await sourceStream.ReadAsync(
                        buffer.AsMemory(0, (int)maxBufferSize),
                        cancellationToken);

                    if (bytesRead is 0)
                        break;

                    var progressPercentage = 10 + (blockIndex + 1) * 90 / totalBlocks;
                    progress.Report((progressPercentage, $"Processing block {blockIndex + 1} of {totalBlocks}..."));

                    DeriveNonce(nonce, blockIndex, chunkNonce);

                    aesGcm.Decrypt(
                        chunkNonce.AsSpan(0, Constants.Security.KeyVault.NonceSize),
                        buffer.AsSpan(0, bytesRead),
                        tag.AsSpan(0, Constants.Security.KeyVault.TagSize),
                        plaintext.AsSpan(0, bytesRead));

                    hashAlgorithm.AppendData(plaintext, 0, bytesRead);

                    await destinationStream.WriteAsync(plaintext.AsMemory(0, bytesRead), cancellationToken);
                    await destinationStream.FlushAsync(cancellationToken);
                }

                return hashAlgorithm.GetCurrentHash();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(tag, true);
                ArrayPool<byte>.Shared.Return(buffer, true);
                ArrayPool<byte>.Shared.Return(plaintext, true);
                ArrayPool<byte>.Shared.Return(chunkNonce, true);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(nonce, true);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] GenerateRandomKey()
    {
        ValidateSecurityOperation();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void LogDebugInfo(string fileId, string filePublicKey)
    {
        ValidateSecurityOperation();

        if (logger.IsEnabled(LogLevel.Debug) is not true) return;

        logger.LogDebug("File Id: {FileId}", fileId);
        logger.LogDebug("File Public Key: {FilePublicKey}", filePublicKey);
    }
}