using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtIssuer
{
    public class User
    {
        /// <summary>
        /// 用户id
        /// </summary>
        public int UserID { get; set; }
        /// <summary>
        /// 用户名
        /// </summary>
        public string UserName { get; set; }
        /// <summary>
        /// 用户角色
        /// </summary>
        public string Role { get; set; }
        /// <summary>
        /// 要设置的过期时间
        /// </summary>
        public string expireDay { get; set; }
    }
}
