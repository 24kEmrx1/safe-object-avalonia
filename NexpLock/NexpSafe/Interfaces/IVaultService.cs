namespace NexpSafe.Interfaces;

public interface IVaultService
{
    Task<string> StoreKeyAsync(string fileId, string filePrivateKey, string filePublicMasterKey,
        byte[] fileHash, string destinationFilePath);

    Task<(string filePrivateKey, byte[] fileHash)> RetrieveKeyAsync(string fileId,
        string filePublicMasterKey, string sourceFilePath);

    void Dispose();
}