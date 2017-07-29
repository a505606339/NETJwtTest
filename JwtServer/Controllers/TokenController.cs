using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using JwtIssuer;
using Newtonsoft.Json.Linq;

namespace JwtServer.Controllers
{
    /// <summary>
    /// jwt协议实现
    /// </summary>
    public class TokenController : ApiController
    {
        /// <summary>
        /// 生成token字符串
        /// </summary>
        /// <param name="User">用户实体</param>
        /// <returns>token字符串</returns>
        [Route("api/token/Audience")]
        [HttpPost]
        public async Task<IHttpActionResult> Audience(User user)
        {
            DateTime expire = DateTime.Now.AddDays(int.Parse(user.expireDay));
            //颁发token类
            TokenIssuer tokenIss = new TokenIssuer();
            var token = await tokenIss.CreateTokenAsHSA(user, expire, "http://localhost");
            return Ok(token);
        }
    }
}
