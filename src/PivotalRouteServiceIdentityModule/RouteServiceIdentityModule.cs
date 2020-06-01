using System;
using System.Security.Claims;
using System.Web;
using System.Linq;

namespace Pivotal.RouteServiceIdentityModule
{
    public class RouteServiceIdentityModule : IHttpModule
    {
        const string CF_IDENTITY_HEADER = "X-CF-Identity";
        const string CF_ROLES_HEADER = "X-CF-Roles";


        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += ContextOnAuthenticateRequest;
        }

        private void ContextOnAuthenticateRequest(object sender, EventArgs e)
        {
            var context = ((HttpApplication) sender).Context;


            var identityHeader = context.Request.Headers.Get(CF_IDENTITY_HEADER);
            var rolesHeader  = context.Request.Headers.Get(CF_ROLES_HEADER);

            if (!String.IsNullOrWhiteSpace(identityHeader))
            {
                
                var nameClaim = new Claim(ClaimTypes.Name, identityHeader);
                var identity = new ClaimsIdentity(new[] { nameClaim }, "RouteService");
                if (rolesHeader != null)
                {
                    var roleClaims = rolesHeader.Split(',').Select(x => new Claim(ClaimTypes.Role, x.Trim()));
                    identity.AddClaims(roleClaims);
                }
                context.User = new ClaimsPrincipal(identity);
            }
        }

        public void Dispose()
        {
        }
    }
}