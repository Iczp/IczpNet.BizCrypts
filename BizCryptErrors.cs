using System.ComponentModel;

namespace IczpNet.BizCrypts
{

    //-40001 ： 签名验证错误
    //-40002 :  xml解析失败
    //-40003 :  sha加密生成签名失败
    //-40004 :  AESKey 非法
    //-40005 :  corpid 校验错误
    //-40006 :  AES 加密失败
    //-40007 ： AES 解密失败
    //-40008 ： 解密后得到的buffer非法
    //-40009 :  base64加密异常
    //-40010 :  base64解密异常
    public enum BizCryptErrors
    {
        [Description("成功")]
        Success = 0,
        [Description("签名验证错误")]
        ValidateSignature = -40001,
        [Description("xml解析失败")]
        ParseXml = -40002,
        [Description("sha加密生成签名失败")]
        ComputeSignature = -40003,
        [Description("AESKey 非法")]
        IllegalAesKey = -40004,
        [Description("corpid 校验错误")]
        ValidateOfficalId = -40005,
        [Description("AES 加密失败")]
        EncryptAES = -40006,
        [Description("AES 解密失败")]
        DecryptAES = -40007,
        [Description("解密后得到的buffer非法")]
        IllegalBuffer = -40008,
        [Description("base64加密异常")]
        EncodeBase64 = -40009,
        [Description("base64解密异常")]
        DecodeBase64 = -40010
    };
}
