using System;
using System.Collections.Generic;
using JWT;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using JwtIssuer.Algorithms;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Principal;
using JWT.Algorithms;
using JWT.Serializers;
using System.Threading.Tasks;

namespace JwtIssuer
{
    public class TokenIssuer
    {
        /// <summary>
        /// 生成token
        /// RS256方式加密,安全度十分高,需要验证服务器持有公钥
        /// 公钥由RSAUtils生成
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="expire">过期时间</param>
        /// <param name="audience">接收者(URL或服务器标识)</param>
        /// <returns></returns>

        public string CreateToken(User user, DateTime expire, string audience)
        {
            //读取文件中的密钥
            string keyDir = AppDomain.CurrentDomain.BaseDirectory;
            Console.Write(keyDir);
            RSAParameters keyParams;
            if (RSAUtils.TryGetKeyParameters(keyDir, true, out keyParams) == false)
            {
                keyParams = RSAUtils.GenerateAndSaveKey(keyDir);
            }
            //建立jti信息
            var handel = new JwtSecurityTokenHandler();
            string jti = audience + user.UserName + expire.ToUniversalTime();
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] data = md5.ComputeHash(System.Text.Encoding.Default.GetBytes(jti));
            jti = BitConverter.ToString(data);//校验的token
            jti = jti.Replace("-", "");
            //clamis-based认证
            var claims = new[]
            {
                new Claim(ClaimTypes.Role, user.Role ?? string.Empty), // 添加角色信息
                new Claim(ClaimTypes.NameIdentifier, user.UserID.ToString()), // 用户 Id ClaimValueTypes.Integer32),
                new Claim("jti",jti,ClaimValueTypes.String) // jti，用来标识 token
            };
            ClaimsIdentity identity = new ClaimsIdentity(new GenericIdentity(user.UserName, "TokenAuth"), claims);

            var token = handel.CreateEncodedJwt(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Issuer = "JwtIssuer",
                Audience = audience,
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(keyParams),
                    SecurityAlgorithms.RsaSha256Signature),
                Subject = identity,
                Expires = expire
            });
            return token;
        }

        /// <summary>
        /// 使用了JWT库而非微软官方库,用hsa加密,实现简单,但存在泄露数据风险,不可存密码一类数据
        /// </summary>
        /// <param name="user">用户实体</param>
        /// <param name="expire">过期时间(UTC)</param>
        /// <param name="audience">访问的网站或标识</param>
        /// <returns></returns>
        public async Task<string> CreateTokenAsHSA(User user, DateTime expire, string audience)
        {
            //jti信息
            string jti = audience + user.UserName + DateToUnix(expire);
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] data = md5.ComputeHash(System.Text.Encoding.Default.GetBytes(jti));
            jti = BitConverter.ToString(data);//校验的token
            jti = jti.Replace("-", "");
            //密钥,用于加密token,后续可用于解密,泄露会导致token伪造
            return await Task.Run(() =>
            {
                byte[] key = System.Text.Encoding.Default.GetBytes("YMSecureKey");
                JwtBase64UrlEncoder base64 = new JwtBase64UrlEncoder();
                var secret = base64.Encode(key);
                var payload = new Dictionary<string, object>
                {
                    {"iss", "JwtIssuer"},
                    {"username", user.UserName},
                    {"userid", user.UserID},
                    {"role", user.Role},
                    {"exp", DateToUnix(expire)},
                    {"iat", DateToUnix(DateTime.Now)},
                    {"sub", audience},
                    {"jti", jti}
                };
                IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
                IJsonSerializer serializer = new JsonNetSerializer();
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            
                    var token = encoder.Encode(payload, secret);
                    return token;
                });
        }

        private string DateToUnix(DateTime dtime)
        {
            DateTime dtStart = TimeZone.CurrentTimeZone.ToLocalTime(new DateTime(1970, 1, 1));
            DateTime dtNow = DateTime.Parse(dtime.ToString());
            TimeSpan toNow = dtNow.Subtract(dtStart);
            string timeStamp = toNow.Ticks.ToString();
            timeStamp = timeStamp.Substring(0, timeStamp.Length - 7);
            return timeStamp;
        }
    }
}
