using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;
public class AccountController(DataContext context,ITokenService tokenService) : BaseApiController
{
[HttpPost("register")] //account/register

public async Task<ActionResult<Userdto>>Register(RegisterDTO registerDTO)
{
    if(await UserExists(registerDTO.Username))
    {
        return BadRequest ("User Already Exists");
    }
    using var hmac=new HMACSHA512();
    var user=new AppUser
    {
        Username=registerDTO.Username.ToLower(),
        PasswordHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
        PasswordSalt=hmac.Key,
    };
        context.Users.Add(user);
        await context.SaveChangesAsync();
        return new Userdto
        {
                Username=user.Username,
                Token= tokenService.CreateToken(user),
        };
}

[HttpPost("login")] //account/login
public async Task<ActionResult<Userdto>> Login(LoginDTO loginDTO)
{
 var user= await context.Users.FirstOrDefaultAsync(x=>
            x.Username==loginDTO.Username.ToLower());

 if(user==null) return  Unauthorized("Invalid Username") ;

 using var hmac=new HMACSHA512(user.PasswordSalt);

 var computeHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));

 for(int i=0 ;i<computeHash.Length; i++)
 {
    if(computeHash[i]!=user.PasswordHash[i]) 
    return Unauthorized("Invalid Password");
 }

   return new Userdto
        {
                Username=user.Username,
                Token= tokenService.CreateToken(user),
        };
 }




private async Task<bool> UserExists(string username)
{
    return await context.Users.AnyAsync(x=>x.Username.ToLower()==username.ToLower());

}






}