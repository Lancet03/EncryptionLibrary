// See https://aka.ms/new-console-template for more information
using EncryptionLibrary;
using static EncryptionLibrary.RSA;

RSA rsa = new EncryptionLibrary.RSA();
var publicKey = rsa.GetPublicKey();
var privateKey = rsa.GetPrivateKey();

Console.WriteLine($"Открытый ключ: (e = {publicKey.e}, n = {publicKey.n})");
Console.WriteLine($"Закрытый ключ: (d = {privateKey.d}, n = {privateKey.n})");

Console.Write("Введите строку для шифрования: ");
string input = Console.ReadLine();

var encrypted = rsa.EncryptString(input);
Console.WriteLine("\nЗашифрованная строка (в виде чисел):");
Console.WriteLine(string.Join(" ", encrypted));

string decrypted = rsa.DecryptString(encrypted);
Console.WriteLine("\nРасшифрованная строка:");
Console.WriteLine(decrypted);