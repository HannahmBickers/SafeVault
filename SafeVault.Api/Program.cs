using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http;
using Utils; 
using SafeVault.Api.Services;


var builder = WebApplication.CreateBuilder(args);

// Register DbService for dependency injection
builder.Services.AddScoped<DbService>();

var app = builder.Build();

app.UseHttpsRedirection();

app.MapPost("/submit", async (HttpRequest request, DbService dbService) =>
{
    var form = await request.ReadFormAsync();
    string username = InputSanitizer.SanitizeInput(form["username"]);
    string email = InputSanitizer.SanitizeInput(form["email"]);

    dbService.AddUser(username, email);

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

    bool success = dbService.RegisterUser(username, email, password, role);

    return success
        ? Results.Ok("User registered successfully.")
        : Results.BadRequest("Registration failed.");
});

// Login an existing user
app.MapPost("/login", async (HttpRequest request, DbService dbService) =>
{
    var form = await request.ReadFormAsync();
    string username = InputSanitizer.SanitizeInput(form["username"]);
    string password = InputSanitizer.SanitizeInput(form["password"]);

    bool authenticated = dbService.AuthenticateUser(username, password);

    return authenticated
        ? Results.Ok("Login successful.")
        : Results.Unauthorized();
});
// Protected admin route
app.MapGet("/admin", (HttpRequest request, DbService dbService) =>
{
    var form = request.Query;

    string username = InputSanitizer.SanitizeInput(form["username"].ToString());

    // Check if user has 'admin' role
    if (dbService.IsUserInRole(username, "admin"))
    {
        return Results.Ok("Welcome, Admin!");
    }

    return Results.Forbid();
});
app.MapPost("/login", async (HttpRequest request, DbService dbService) =>
{
    var form = await request.ReadFormAsync();
    string username = InputSanitizer.SanitizeInput(form["username"]);
    string password = InputSanitizer.SanitizeInput(form["password"]);

    if (dbService.AuthenticateUser(username, password))
    {
        return Results.Ok("Login successful.");
    }

    return Results.Unauthorized();
});
app.MapPost("/admin", async (HttpRequest request, DbService dbService) =>
{
    var form = await request.ReadFormAsync();
    string username = InputSanitizer.SanitizeInput(form["username"]);

    if (dbService.IsUserInRole(username, "admin"))
    {
        return Results.Ok("Welcome, Admin!");
    }

    return Results.Forbid();
});

app.Run();
