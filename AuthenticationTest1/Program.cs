namespace AuthenticationTest1
{
    class Program
    {
        static void Main(string[] args)
        {
            //var acc = new Account("something@something.com", "something");
            //System.Console.WriteLine("{0}\n{1}", acc.Salt.ToHexString(), acc.PasswordVerifier.ToHexString());

            var acc = new Account("slime1st@yandex.ru", "123456789", "DF66E7B36B9B1C14154580B48AB027C07275939FE2BFEC3F185A81F1BB1E2EE9");
            System.Console.WriteLine("{0}\n{1}", acc.Salt.ToHexString(), acc.PasswordVerifier.ToHexString());
        }
    }
}
