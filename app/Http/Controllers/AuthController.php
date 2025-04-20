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