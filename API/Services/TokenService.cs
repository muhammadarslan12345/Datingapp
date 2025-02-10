using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using Microsoft.IdentityModel.Tokens;

namespace API;

public class TokenService(IConfiguration config) : ITokenService
{
    public string CreateToken(AppUser user)
    {
        var tokenKey=config["TokenKey"] ?? throw new Exception("Cannot access the tpken ley from appsettings");
        if(tokenKey.Length < 64) throw new Exception("Length is not greater than 64 ");
        var key= new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey));

        var claims=new List <Claim>
        {
         new(ClaimTypes.NameIdentifier ,user.Username),
        };


        var creds=new SigningCredentials(key, SecurityAlgorithms.Aes256CbcHmacSha512);

        var tokenDescriptor= new SecurityTokenDescriptor
        {

            Subject=new ClaimsIdentity(claims),
            Expires=DateTime.UtcNow.AddDays(7),
            SigningCredentials=creds,
        };

            var tokenHandler=new JwtSecurityTokenHandler();
            var token=tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);

    }
}