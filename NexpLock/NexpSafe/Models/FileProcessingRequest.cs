namespace NexpSafe.Models;

public sealed record FileProcessingRequest(string FileId, string SourcePath, string DestinationPath);