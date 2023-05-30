using System;
using System.Text;
using System.Collections;
using System.Security.Cryptography;

namespace IczpNet.BizCrypts
{
    /// <summary>
    /// BizCrypt
    /// </summary>
    public class BizCrypt
    {
        /// <summary>
        /// 开发者设置的Token
        /// </summary>
        public virtual string Token { get; private set; }
        /// <summary>
        /// 开发者设置的EncodingAESKey
        /// </summary>
        public virtual string EncodingAesKey { get; private set; }
        /// <summary>
        /// 公众号的OfficalId
        /// </summary>
        public virtual string OfficalId { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="token">开发者设置的Token</param>
        /// <param name="encodingAesKey">开发者设置的EncodingAESKey</param>
        /// <param name="officalId">公众号的OfficalId</param>
        public BizCrypt(string token, string encodingAesKey, string officalId)
        {
            Token = token;
            OfficalId = officalId;
            EncodingAesKey = encodingAesKey;
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <returns></returns>
        public string Decrypt(string cipherText)
        {
            var cpid = "";
            return Cryptography.AESDecrypt(cipherText, EncodingAesKey, ref cpid);
        }
        /// <summary>
        /// 消息加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <returns></returns>
        public string Encrypt(string plaintext)
        {
            try
            {
                return Cryptography.AESEncrypt(plaintext, EncodingAesKey, OfficalId);
            }
            catch (Exception)
            {
                return null;
            }
        }
        /// <summary>
        ///  验证签名
        /// </summary>
        /// <param name="signature">签名</param>
        /// <param name="token">开发者设置的Token</param>
        /// <param name="timeStamp">时间戳</param>
        /// <param name="nonce">随机数</param>
        /// <param name="cipherText">密文</param>
        /// <returns></returns>
        public static bool VerifySignature(string signature, string token, string timeStamp, string nonce, string cipherText)
        {
            return signature.Equals(GenerateSignature(token, timeStamp, nonce, cipherText));
        }
        /// <summary>
        /// 生成签名
        /// </summary>
        /// <param name="token">开发者设置的Token</param>
        /// <param name="timeStamp">时间戳</param>
        /// <param name="nonce">随机数</param>
        /// <param name="cipherText">密文</param>
        /// <returns></returns>
        public static string GenerateSignature(string token, string timeStamp, string nonce, string cipherText)
        {
            var arrList = new ArrayList
            {
                token,
                timeStamp,
                nonce,
                cipherText
            };
            arrList.Sort(new DictionarySort());
            string raw = "";
            for (int i = 0; i < arrList.Count; ++i)
            {
                raw += arrList[i];
            }

            try
            {
                var sha = new SHA1CryptoServiceProvider();
                var enc = new ASCIIEncoding();
                byte[] dataToHash = enc.GetBytes(raw);
                byte[] dataHashed = sha.ComputeHash(dataToHash);
                var hash = BitConverter.ToString(dataHashed).Replace("-", "").ToLower();
                return hash;
            }
            catch (Exception)
            {
                return null;
            }
        }
        /// <summary>
        /// 使用Guid产生的种子生成真随机数
        /// </summary>
        /// <param name="length">长度</param>
        /// <param name="codeSerial">取值范围</param>
        /// <returns></returns>
        public static string CreateRandCode(int length, string codeSerial = "234567acdefhijkmnprstACDEFGHJKMNPQRSUVWXYZ")
        {
            //string codeSerial = "234567acdefhijkmnprstACDEFGHJKMNPQRSUVWXYZ";
            var arr = codeSerial.ToCharArray();
            string result = "";
            Random random = new Random(Guid.NewGuid().GetHashCode());
            for (int i = 0; i < length; i++)
            {
                var index = random.Next(0, length - 1);
                result += arr[index];
            }
            return result;
        }
    }
}
