# Laravel Sanctum API

How we can use Sanctum API in Laravel project.

## Deployment

To deploy this project run

```bash
composer create-project laravel/laravel sanctum-api
```

```bash
cd sanctum-api
```

```bash
php artisan install:api
```

```bash
composer require laravel/sanctum
```

```bash
php artisan vendor:publish --tag=sanctum-migrations
```

```bash
app/Models/User.php

use Laravel\Sanctum\HasApiTokens;
use Illuminate\Contracts\Auth\MustVerifyEmail;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $fillable = ['name', 'email', 'password', 'role'];
}
```

```bash
php artisan make:migration add_role_to_users_table

public function up()
{
    Schema::table('users', function (Blueprint $table) {
        $table->string('role')->default('user');
    });
}
```

```bash
php artisan migrate
```

```bash
php artisan make:controller AuthController
```

```bash
<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Notifications\VerifyEmailWithApi;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Auth\Events\Registered;
use Illuminate\Validation\ValidationException;
use Laravel\Sanctum\PersonalAccessToken;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed',
        ]);

        $user = User::create(array_merge($validated, [
            'password' => Hash::make($validated['password']),
            'role' => $request->role ?? 'user',
        ]));

        // $user->sendEmailVerificationNotification();
        // event(new Registered($user));
        $user->notify(new VerifyEmailWithApi());


        return response()->json([
            'user' => $user,
            'token' => $user->createToken('api-token')->plainTextToken,
            'message' => 'Registered. Please verify your email.'
        ], 201);
    }

    public function login(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        // Find the user by email
        $user = User::where('email', $validated['email'])->first();

        // Check if the user exists and the password matches
        if ($user && Hash::check($validated['password'], $user->password)) {

            return response()->json([
                'user' => $user,
                'token' => $user->createToken('api-token')->plainTextToken,
            ]);
        }

        throw ValidationException::withMessages([
            'email' => ['The provided credentials are incorrect.'],
        ]);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logged out']);
    }

    public function verifyEmail(Request $request)
    {
        if ($request->user()->hasVerifiedEmail()) {
            return response()->json(['message' => 'Email already verified.'], 200);
        }

        $request->user()->markEmailAsVerified();
        return response()->json(['message' => 'Email verified successfully'], 200);
    }

    // public route to verify email with token through query param
    public function confirmEmail(Request $request)
    {
        $token = $request->query('token');

        $user = PersonalAccessToken::findToken($token)?->tokenable;

        if (!$user || !$user instanceof User) {
            return response()->json(['message' => 'Invalid token or expired.'], 401);
        }

        if (!$user->hasVerifiedEmail()) {
            $user->markEmailAsVerified();
        }

        // Optional: delete token so it can't be reused
        $user->tokens()->where('name', 'verify-email')->delete();

        return response()->json(['message' => 'Email verified successfully.'], 200);
    }
}
```

```bash
php artisan make:model Post -mcr
```

```bash
public function up()
{
    Schema::create('posts', function (Blueprint $table) {
        $table->id();
        $table->foreignId('user_id')->constrained()->onDelete('cascade');
        $table->string('title');
        $table->text('content');
        $table->timestamps();
    });
}
```

```bash
User.php

public function posts()
{
    return $this->hasMany(Post::class);
}
```

```bash
<?php

namespace App\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    use HasFactory;
    protected $fillable = ['user_id', 'title', 'content'];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
```

```bash
<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;

class PostController extends Controller
{
    use AuthorizesRequests;

    public function index()
    {
        return Post::with('user')->get();
    }

    public function store(Request $request)
    {
        $request->validate([
            'title' => 'required|string',
            'content' => 'required|string',
        ]);

        return $request->user()->posts()->create($request->only('title', 'content'));
    }

    public function show(Post $post)
    {
        $this->authorize('show', $post);
        return $post;
    }

    public function update(Request $request, Post $post)
    {
        $this->authorize('update', $post);
        $post->update($request->only('title', 'content'));
        return $post;
    }

    public function destroy(Post $post)
    {
        $this->authorize('delete', $post);
        $post->delete();
        return response()->noContent();
    }
}
```

```bash
php artisan make:middleware RoleMiddleware
```

```bash
RoleMiddleware.php

public function handle($request, Closure $next, ...$roles)
{
    if (!in_array($request->user()?->role, $roles)) {
        return response()->json(['message' => 'Forbidden'], 403);
    }

    return $next($request);
}
```

Optional : Fix for authorize() Error in PostController.php

```bash
Add the Trait

At the top of your PostController.php

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
class PostController extends Controller

{
    use AuthorizesRequests;

    // your methods...
}
```

**Send Custom Email with Sanctum Token for Verification**

```bash
php artisan make:notification VerifyEmailWithApi
```

Then in app/Notifications/VerifyEmailWithApi.php:

```bash
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Messages\MailMessage;

class VerifyApiEmail extends Notification
{
    public function toMail($notifiable)
    {
        $token = $notifiable->createToken('verify-email')->plainTextToken;

        return (new MailMessage)
            ->subject('Verify Your Email Address')
            ->line('Click the button below to verify your email address.')
            ->action('Verify Email', url("/api/auth/verify/email?token={$token}"))
            ->line('If you did not create an account, no further action is required.');
    }
}

```

**Send the Notification During Registration**

```bash
$user->notify(new VerifyEmailWithApi());
```

**Email Verification with Token**

```bash
http://127.0.0.1:8000/api/auth/verify/email?token={token}
Example:
http://127.0.0.1:8000/api/auth/verify/email?token=1|GP2Wgaze6CLxjd1SDVLLijSg3Dc7zCed8uggScY263755fe0
```

**Public Route to Trigger Sanctum Token Verification**

This route is unauthenticated because it uses the token from the email:

```bash
Route::get('verify/email', [AuthController::class, 'confirmEmail']);
```

In AuthController.php:

```bash
// public route to verify email with token through query param

public function confirmEmail(Request $request)
{
    $token = $request->query('token');

    $user = PersonalAccessToken::findToken($token)?->tokenable;

    if (!$user || !$user instanceof User) {
        return response()->json(['message' => 'Invalid token or expired.'], 401);
    }

    if (!$user->hasVerifiedEmail()) {
        $user->markEmailAsVerified();
    }

    // Optional: delete token so it can't be reused
    $user->tokens()->where('name', 'verify-email')->delete();

    return response()->json(['message' => 'Email verified successfully.'], 200);
}
```

**ALL ROUTES**

```bash
<?php

use App\Models\User;
use App\Http\Middleware\RoleMiddleware;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\PostController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Foundation\Auth\EmailVerificationRequest;

Route::get('/users', fn() => User::all());

Route::prefix('auth')->group(function () {
    // Registration and Login routes
    Route::post('/register', [AuthController::class, 'register']);
    Route::get('/verify/email', [AuthController::class, 'confirmEmail']);
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:sanctum');
});

Route::middleware(['auth:sanctum', 'verified'])->group(function () {
    Route::apiResource('posts', PostController::class);
});

Route::middleware(['auth:sanctum', RoleMiddleware::class . ':admin'])->group(function () {
    Route::post('/admin-only', fn() => response()->json(['message' => 'Admin area']));
});

// Email verification routes protected by Sanctum
Route::middleware(['auth:sanctum'])->group(function () {
    Route::post('email/verify', [AuthController::class, 'verifyEmail']);

    // Email verification route
    Route::get('/email/verify/{id}/{hash}', function (EmailVerificationRequest $request) {
        // Fulfill the email verification process
        $request->fulfill();

        // Return a JSON response instead of redirect
        return response()->json([
            'message' => 'Email successfully verified!',
        ]);
    })->middleware(['signed'])->name('verification.verify');

    // Resend email verification link
    Route::post('/email/verification-notification', function (Request $request) {
        if ($request->user()->hasVerifiedEmail()) {
            return response()->json(['message' => 'Already verified']);
        }

        // Send the verification link again
        $request->user()->sendEmailVerificationNotification();

        return response()->json(['message' => 'Verification link sent!']);
    })->middleware(['throttle:6,1']);
});
```

Optional for json response

```bash
php artisan make:middleware ForceJsonResponse
```

```bash
ForceJsonResponse.php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class ForceJsonResponse
{
    public function handle(Request $request, Closure $next)
    {
        $request->headers->set('Accept', 'application/json');
        return $next($request);
    }
}

routes/api.php -> add routes force to json response

Route::middleware(['json.response', 'auth:sanctum'])->group(function () {
    Route::apiResource('posts', PostController::class);
    // add all routes here...
});

or

use App\Http\Middleware\ForceJsonResponse;

Route::middleware([ForceJsonResponse::class])->group(function () {
    // all your routes
});

```

Customize Unauthenticated Handler (Optional)

```bash
php artisan make:exception Handler
```

In app/Exceptions/Handler.php, override unauthenticated():

```bash
use Illuminate\Auth\AuthenticationException;

protected function unauthenticated($request, AuthenticationException $exception)
{
    return response()->json(['message' => 'Unauthenticated'], 401);
}
```

Test With Proper Headers

```bash
When making requests, use:

    Accept: application/json

    Authorization: Bearer YOUR_TOKEN
```
