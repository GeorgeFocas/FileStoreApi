
using NetworkShareHelpers;

var checker = new SecureNetworkFileChecker();

var result = await checker.FileExistsAsync(
    @"\\PTPO-L-007\TheFolder\somefile.txt");

Console.WriteLine($"{result.Exists} | {result.Failure} | {result.Message}");
