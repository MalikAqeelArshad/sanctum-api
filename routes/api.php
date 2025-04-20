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
    Route::post('/email/verify', [AuthController::class, 'verifyEmail']);

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