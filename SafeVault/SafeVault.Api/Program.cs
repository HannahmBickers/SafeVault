using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http;
using Utils;
using SafeVault.Api.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<DbService>();

var app = builder.Build();

app.UseHttpsRedirection();

// Handle user submission
app.MapPost("/submit", async (HttpRequest request, DbService dbService) =>
{
    var form = await request.ReadFormAsync();
    // Sanitize all user input to help prevent XSS and injection attacks
    string username = InputSanitizer.SanitizeInput(form["username"]);
    string email = InputSanitizer.SanitizeInput(form["email"]);

    // Additional validation for dangerous characters 
    if (username.Contains("'") || username.Contains("--") || username.Contains(";"))
    {
        return Results.BadRequest("Invalid characters in username.");
    }

    dbService.AddUser(username, email);

    // Do not reflect user input in responses to avoid XSS
    return Results.Ok("User submitted safely.");
});

// Register a new user
app.MapPost("/register", async (HttpRequest request, DbService dbService) =>
{
    var form = await request.ReadFormAsync();
    
    string username = InputSanitizer.SanitizeInput(form["username"].ToString());
    string email = InputSanitizer.SanitizeInput(form["email"].ToString());
    string password = InputSanitizer.SanitizeInput(form["password"].ToString());
    string role = InputSanitizer.SanitizeInput(form["role"].ToString());

    if (username.Contains("'") || username.Contains("--") || username.Contains(";"))
    {
        return Results.BadRequest("Invalid characters in username.");
    }

    bool success = dbService.RegisterUser(username, email, password, role);

   
    return success
        ? Results.Ok("User registered successfully.")
        : Results.BadRequest("Registration failed.");
});

// Login endpoint
app.MapPost("/login", async (HttpRequest request, DbService dbService) =>
{
    var form = await request.ReadFormAsync();
    string rawUsername = form["username"];
    string password = InputSanitizer.SanitizeInput(form["password"]);

    if (rawUsername.Contains("'") || rawUsername.Contains("--") || rawUsername.Contains(";"))
    {
        return Results.BadRequest("Invalid characters in username.");
    }

    string username = InputSanitizer.SanitizeInput(rawUsername);

    bool authenticated = dbService.AuthenticateUser(username, password);

    
    return authenticated
        ? Results.Ok("Login successful.")
        : Results.Unauthorized();
});


// Protected admin route
app.MapPost("/admin", async (HttpRequest request, DbService dbService) =>
{
    var form = await request.ReadFormAsync();
    string username = InputSanitizer.SanitizeInput(form["username"]);

    if (username.Contains("'") || username.Contains("--") || username.Contains(";"))
    {
        return Results.BadRequest("Invalid characters in username.");
    }

    
    if (dbService.IsUserInRole(username, "admin"))
    {
        return Results.Ok("Welcome, Admin!");
    }

    return Results.Forbid();
});

app.Run();

