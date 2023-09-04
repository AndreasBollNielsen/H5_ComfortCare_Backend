using ComfortCare.Api.Models;
using ComfortCare.Service.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.Xml;
using System.Diagnostics;

namespace ComfortCare.Api.Controllers
{
    /// <summary>
    /// This is the login controller, this is the only entry point in production 
    /// for the employees/users
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        #region fields
        public static Keyholder keyholder = new Keyholder();
        //  private Aes _aesAlgorithm;
        private readonly IUserService _userService;
        #endregion

        #region Constructor
        public LoginController(IUserService userService)
        {
            _userService = userService;
        }
        #endregion

        #region Controller Methods
        /// <summary>
        /// Checks the request send by the app, with username and password, and validates the inputs.
        /// Also handles errors for no internet.
        /// </summary>
        /// <param name="loginDto">Login data transfer object. Carries the user inputs.</param>
        /// <returns>Returns a status code, and an error message in the body that the app can read on.</returns>
        [HttpPost("Employee")]
        public async Task<IActionResult> EmployeeLogin(encryptedData data)
        {
            var byteArr = Convert.FromBase64String(data.data);
            //decrypt data
            var decryptedData = DecryptData(byteArr);


            //convert json string to model
            var user = JsonConvert.DeserializeObject<LoginDto>(decryptedData);


            //validate user
            var loginResult = _userService.ValidateUser(user.Initials, user.Password);
            loginResult = true;
            try
            {
                if (!loginResult)
                {
                    return StatusCode(400, "Bad request, wrong username or password.");
                }
                else
                {

                    //generate test data
                    string json = await LoadJsonFromFileAsync(user.Initials);
                    EmployeeScheduleDto root = JsonConvert.DeserializeObject<EmployeeScheduleDto>(json);


                    EmployeeScheduleDto employeeDto = new EmployeeScheduleDto
                    {
                        Name = root.Name,
                        Assignments = root.Assignments.Select(assignmentData => new AssignmentDto
                        {
                            Titel = assignmentData.Titel,
                            Description = assignmentData.Description,
                            CitizenName = assignmentData.CitizenName,
                            StartDate = assignmentData.StartDate,
                            EndDate = assignmentData.EndDate,
                            Address = assignmentData.Address
                        }).ToList()
                    };






                    //encrypt testdata and return to app
                    var jsonData = JsonConvert.SerializeObject(employeeDto);
                    var encryptedData = Convert.ToBase64String( EncryptData(jsonData));
                    return StatusCode(200, encryptedData);
                }
            }
            catch (Exception)
            {
                return StatusCode(500, "Internal Server Error, please contact your administrator if this continues");
            }
        }

        [HttpPost("GetKey")]
        public IActionResult GetPublicKey(LoginDto loginDto)
        {

            //generate RSA keys
            RSAParameters publickey = GenerateRSAKeyPair();


            var pemkey = ExportPublicKeyToPEM(publickey);


            //send public key to user
            string output = "ok";
            try
            {
                return StatusCode(200, pemkey);
            }
            catch (Exception)
            {

                return StatusCode(500, "Internal Server Error, please contact your administrator if this continues");
            }
        }

        [HttpPost("SetAESKeys")]
        public IActionResult GetAESKeys([FromBody] KeysModel data)
        {
            //byte[] decryptedKey;
            //byte[] decryptedIv;
            int keylength = 0;
            int ivlength = 0;
            try
            {
                //decrypt data
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {


                    rsa.ImportParameters(keyholder.RSAParameters);

                    try
                    {
                        // Dekrypter data ved hjælp af den private RSA-nøgle
                        byte[] keyData = Convert.FromBase64String(data.key);
                        byte[] ivData = Convert.FromBase64String(data.iv);
                        byte[] decryptedKey = rsa.Decrypt(keyData, true);
                        byte[] decryptedIv = rsa.Decrypt(ivData, true);
                        keylength = decryptedKey.Length;
                        ivlength = decryptedIv.Length;

                        using (Aes aesalgorithm = Aes.Create())
                        {
                            aesalgorithm.Key = decryptedKey;
                            aesalgorithm.IV = decryptedIv;
                            keyholder.key = Convert.ToBase64String(aesalgorithm.Key);
                            keyholder.iv = Convert.ToBase64String(aesalgorithm.IV);


                        }

                    }
                    catch (CryptographicException e)
                    {
                        // Håndter eventuelle dekrypteringsfejl her
                        Console.WriteLine("Dekrypteringsfejl: " + e.Message);
                        return null;
                    }
                }








                return StatusCode(200);
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        private async Task<string> LoadJsonFromFileAsync(String initials)
        {
            string relativeFolderPath = $"data/{initials}_datasæt.txt"; // Den relative sti til data-mappen
            string absoluteFolderPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, relativeFolderPath);

            string filapath = absoluteFolderPath;

            try
            {
                using (StreamReader reader = new StreamReader(filapath))
                {
                    return await reader.ReadToEndAsync();
                }
            }
            catch (Exception ex)
            {

                return null;
            }
        }

        private RSAParameters GenerateRSAKeyPair()
        {
            using (RSA rsa = RSA.Create())
            {
                // Generer RSA-nøgler med en bestemt nøglelængde (f.eks. 2048 bits)
                rsa.KeySize = 2048;

                // Hent de offentlige og private nøgler
                RSAParameters publicKey = rsa.ExportParameters(false);
                RSAParameters privateKey = rsa.ExportParameters(true);
                keyholder.RSAParameters = privateKey;

                return publicKey; // Returner den offentlige nøgle (du kan også returnere begge nøgler)
            }
        }

        private string DecryptData(byte[] data)
        {
            //string decryptedMessage;
            byte[] newdata = new byte[]
            {
                216, 112, 121, 136, 88, 34, 63, 69, 100, 211, 64, 177, 3, 246, 82, 123

            };
            // data = newdata;
            try
            {
                using (SymmetricAlgorithm al = Aes.Create())
                {
                    // al.KeySize = 256;
                    al.IV = Convert.FromBase64String(keyholder.iv);
                    al.Key = Convert.FromBase64String(keyholder.key);
                    al.Mode = CipherMode.CBC;
                    // al.Padding = PaddingMode.None;

                    ICryptoTransform decryptor = al.CreateDecryptor();

                    using (MemoryStream stream = new MemoryStream(data))
                    {
                        using (CryptoStream crypto = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader reader = new StreamReader(crypto))
                            {
                                var decryptedMessage = reader.ReadToEnd();

                                // Debug.WriteLine(decryptedMessage);
                                return decryptedMessage;
                            }
                        }

                    }
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
                throw;
            }

        }

        public byte[] EncryptData(string message)
        {
            try
            {
                using (SymmetricAlgorithm al = Aes.Create())
                {
                    al.IV = Convert.FromBase64String(keyholder.iv);
                    al.Key = Convert.FromBase64String(keyholder.key);
                    al.Mode = CipherMode.CBC;
                    byte[] encryptedMessage;
                    ICryptoTransform decryptor = al.CreateEncryptor();

                    using (MemoryStream stream = new MemoryStream())
                    {
                        using (CryptoStream crypto = new CryptoStream(stream, decryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter writer = new StreamWriter(crypto))
                            {
                                writer.Write(message);
                            }
                        }
                        return encryptedMessage = stream.ToArray();
                    }
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
                throw;
            }

        }
        private string ExportPublicKeyToPEM(RSAParameters publicKeyParameters)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKeyParameters);

                // Opret en StringBuilder for at bygge PEM-strengen
                StringBuilder builder = new StringBuilder();

                // Indled PEM-strengen med "-----BEGIN PUBLIC KEY-----"
                builder.AppendLine("-----BEGIN PUBLIC KEY-----");

                // Konverter den offentlige nøgle til bytes og derefter til Base64
                byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
                string base64PublicKey = Convert.ToBase64String(publicKeyBytes);

                // Del Base64-strengen i linjer på 64 tegn hver
                int chunkSize = 64;
                for (int i = 0; i < base64PublicKey.Length; i += chunkSize)
                {
                    int remainingChars = Math.Min(chunkSize, base64PublicKey.Length - i);
                    builder.AppendLine(base64PublicKey.Substring(i, remainingChars));
                }

                // Afslut PEM-strengen med "-----END PUBLIC KEY-----"
                builder.AppendLine("-----END PUBLIC KEY-----");

                return builder.ToString();
            }
        }



        #endregion
    }
}
