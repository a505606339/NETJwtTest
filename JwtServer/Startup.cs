using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin;
using Owin;
using System.Security.Cryptography;
using JwtIssuer.Algorithms;

[assembly: OwinStartup(typeof(JwtServer.Startup))]

namespace JwtServer
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);

            //针对严格加密的jwt初始化
            string keyDir = AppDomain.CurrentDomain.BaseDirectory;
            Console.Write(keyDir);
            RSAParameters keyParams;
            if (RSAUtils.TryGetKeyParameters(keyDir, true, out keyParams) == false)
            {
                keyParams = RSAUtils.GenerateAndSaveKey(keyDir);
            }
        }
    }
}
