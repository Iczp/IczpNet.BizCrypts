using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Net;
namespace IczpNet.BizCrypts
{
    /// <summary>
    /// 密码学
    /// </summary>
    public class Cryptography
    {
        /// <summary>
        /// 获取主机到网络的订单值
        /// </summary>
        /// <param name="inval">输入值</param>
        /// <returns></returns>
        public static uint HostToNetworkOrder(uint inval)
        {
            uint outval = 0;
            for (int i = 0; i < 4; i++)
                outval = (outval << 8) + ((inval >> (i * 8)) & 255);
            return outval;
        }
        /// <summary>
        /// 获取主机到网络的订单值
        /// </summary>
        /// <param name="inval">输入值</param>
        /// <returns></returns>
        public static int HostToNetworkOrder(int inval)
        {
            Int32 outval = 0;
            for (int i = 0; i < 4; i++)
                outval = (outval << 8) + ((inval >> (i * 8)) & 255);
            return outval;
        }
        /// <summary>
        /// 解密方法
        /// </summary>
        /// <param name="Input">密文</param>
        /// <param name="EncodingAESKey">秘钥</param>
        /// <param name="chatObjectId">企业id</param>
        /// <returns></returns>
        /// 
        public static string AESDecrypt(string Input, string EncodingAESKey, ref string chatObjectId)
        {
            byte[] Key;
            Key = Convert.FromBase64String(EncodingAESKey + "=");

            foreach (var b in Key)
            {
                Console.WriteLine(b);
            }


            byte[] Iv = new byte[16];
            Array.Copy(Key, Iv, 16);
            byte[] btmpMsg = AESDecrypt(Input, Iv, Key);

            int len = BitConverter.ToInt32(btmpMsg, 16);
            len = IPAddress.NetworkToHostOrder(len);


            byte[] bMsg = new byte[len];
            byte[] bChatObjectId = new byte[btmpMsg.Length - 20 - len];
            Array.Copy(btmpMsg, 20, bMsg, 0, len);
            Array.Copy(btmpMsg, 20+len , bChatObjectId, 0, btmpMsg.Length - 20 - len);
            string oriMsg = Encoding.UTF8.GetString(bMsg);
            chatObjectId = Encoding.UTF8.GetString(bChatObjectId);

            
            return oriMsg;
        }
        /// <summary>
        /// 加密方法
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="encodingAESKey">秘钥</param>
        /// <param name="chatObjectId">公众号Id</param>
        /// <returns></returns>
        public static string AESEncrypt(string ciphertext, string encodingAESKey, string chatObjectId)
        {
            byte[] Key;
            Key = Convert.FromBase64String(encodingAESKey + "=");
            byte[] Iv = new byte[16];
            Array.Copy(Key, Iv, 16);
            string Randcode = CreateRandCode(16);
            byte[] bRand = Encoding.UTF8.GetBytes(Randcode);
            byte[] bchatObjectId = Encoding.UTF8.GetBytes(chatObjectId);
            byte[] btmpMsg = Encoding.UTF8.GetBytes(ciphertext);
            byte[] bMsgLen = BitConverter.GetBytes(HostToNetworkOrder(btmpMsg.Length));
            byte[] bMsg = new byte[bRand.Length + bMsgLen.Length + bchatObjectId.Length + btmpMsg.Length];

            Array.Copy(bRand, bMsg, bRand.Length);
            Array.Copy(bMsgLen, 0, bMsg, bRand.Length, bMsgLen.Length);
            Array.Copy(btmpMsg, 0, bMsg, bRand.Length + bMsgLen.Length, btmpMsg.Length);
            Array.Copy(bchatObjectId, 0, bMsg, bRand.Length + bMsgLen.Length + btmpMsg.Length, bchatObjectId.Length);
   
            return AESEncrypt(bMsg, Iv, Key);
        }
        /// <summary>
        /// 创建随机码
        /// </summary>
        /// <param name="codeLen">码长度</param>
        /// <returns></returns>
        public static string CreateRandCode(int codeLen)
        {
            string codeSerial = "2,3,4,5,6,7,a,c,d,e,f,h,i,j,k,m,n,p,r,s,t,A,C,D,E,F,G,H,J,K,M,N,P,Q,R,S,U,V,W,X,Y,Z";
            if (codeLen == 0)
            {
                codeLen = 16;
            }
            string[] arr = codeSerial.Split(',');
            string code = "";
            int randValue = -1;
            Random rand = new Random(unchecked((int)DateTime.Now.Ticks));
            for (int i = 0; i < codeLen; i++)
            {
                randValue = rand.Next(0, arr.Length - 1);
                code += arr[randValue];
            }
            return code;
        }

        /// <summary>
        /// 使用Guid产生的种子生成真随机数
        /// </summary>
        /// <param name="length">长度</param>
        /// <param name="codeSerial">取值范围</param>
        /// <returns></returns>
        public static string CreateRandCodeByGuid(int length, string codeSerial = "234567acdefhijkmnprstACDEFGHJKMNPQRSUVWXYZ")
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
        /// <summary>
        /// 加密方法
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="iv">Iv</param>
        /// <param name="key">Key</param>
        /// <returns></returns>
        private static string AESEncrypt(string ciphertext, byte[] iv, byte[] key)
        {
            var aes = new RijndaelManaged();
            //秘钥的大小，以位为单位
            aes.KeySize = 256;
            //支持的块大小
            aes.BlockSize = 128;
            //填充模式
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = iv;
            var encrypt = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] xBuff = null;

            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encrypt, CryptoStreamMode.Write))
                {
                    byte[] xXml = Encoding.UTF8.GetBytes(ciphertext);
                    cs.Write(xXml, 0, xXml.Length);
                }
                xBuff = ms.ToArray();
            }
            string Output = Convert.ToBase64String(xBuff);
            return Output;
        }
        /// <summary>
        /// 加密方法
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="iv">Iv</param>
        /// <param name="key">Key</param>
        /// <returns></returns>
        private static string AESEncrypt(byte[] ciphertext, byte[] iv, byte[] key)
        {
            var aes = new RijndaelManaged();
            //秘钥的大小，以位为单位
            aes.KeySize = 256;
            //支持的块大小
            aes.BlockSize = 128;
            //填充模式
            //aes.Padding = PaddingMode.PKCS7;
            aes.Padding = PaddingMode.None;
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = iv;
            var encrypt = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] xBuff = null;

            #region 自己进行PKCS7补位，用系统自己带的不行
            byte[] msg = new byte[ciphertext.Length + 32 - ciphertext.Length % 32];
            Array.Copy(ciphertext, msg, ciphertext.Length);
            byte[] pad = KCS7Encoder(ciphertext.Length);
            Array.Copy(pad, 0, msg, ciphertext.Length, pad.Length);
            #endregion

            #region 注释的也是一种方法，效果一样
            //ICryptoTransform transform = aes.CreateEncryptor();
            //byte[] xBuff = transform.TransformFinalBlock(msg, 0, msg.Length);
            #endregion

            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encrypt, CryptoStreamMode.Write))
                {
                    cs.Write(msg, 0, msg.Length);
                }
                xBuff = ms.ToArray();
            }

            String Output = Convert.ToBase64String(xBuff);
            return Output;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="text_length"></param>
        /// <returns></returns>
        private static byte[] KCS7Encoder(int text_length)
        {
            int block_size = 32;
            // 计算需要填充的位数
            int amount_to_pad = block_size - (text_length % block_size);
            if (amount_to_pad == 0)
            {
                amount_to_pad = block_size;
            }
            // 获得补位所用的字符
            char pad_chr = ToChar(amount_to_pad);
            string tmp = "";
            for (int index = 0; index < amount_to_pad; index++)
            {
                tmp += pad_chr;
            }
            return Encoding.UTF8.GetBytes(tmp);
        }
        
        /**
         * 将数字转化成ASCII码对应的字符，用于对明文进行补码
         * 
         * @param a 需要转化的数字
         * @return 转化得到的字符
         */
        static char ToChar(int n)
        {

            byte target = (byte)(n & 0xFF);
            return (char)target;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        private static byte[] AESDecrypt(String ciphertext, byte[] iv, byte[] key)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;
            var decrypt = aes.CreateDecryptor(aes.Key, aes.IV);
            byte[] xBuff = null;
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, decrypt, CryptoStreamMode.Write))
                {
                    byte[] xXml = Convert.FromBase64String(ciphertext);
                    byte[] msg = new byte[xXml.Length + 32 - xXml.Length % 32];
                    Array.Copy(xXml, msg, xXml.Length);
                    cs.Write(xXml, 0, xXml.Length);
                }
                xBuff = Decode2(ms.ToArray());
            }
            return xBuff;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="decrypted"></param>
        /// <returns></returns>
        private static byte[] Decode2(byte[] decrypted)
        {
            int pad = decrypted[decrypted.Length - 1];
            if (pad < 1 || pad > 32)
            {
                pad = 0;
            }
            byte[] res = new byte[decrypted.Length - pad];
            Array.Copy(decrypted, 0, res, 0, decrypted.Length - pad);
            return res;
        }
    }
}
