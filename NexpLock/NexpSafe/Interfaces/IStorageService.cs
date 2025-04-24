using NexpSafe.Models;

namespace NexpSafe.Interfaces;

public interface IStorageService
{
    Task EncryptFileAsync(FileProcessingRequest request, string filePublicMasterKey,
        CancellationToken cancellationToken, IProgress<(double percentage, string message)> progress);

    Task DecryptFileAsync(FileProcessingRequest request, string filePublicMasterKey,
        CancellationToken cancellationToken, IProgress<(double percentage, string message)> progress);

    void Dispose();
}