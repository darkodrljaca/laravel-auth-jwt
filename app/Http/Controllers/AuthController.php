<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{

    public function register(Request $request)
    {
        $user = User::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password'))
        ]);
        return $user;
    }

    public function login(Request $request)
    {
        if(!Auth::attempt([
            'email' => $request->input('email'),
            'password' => $request->input('password')
        ])) {
            return response([
                'message' => 'Invalid credentials!'
            ], Response::HTTP_UNAUTHORIZED);
        }

        $user = Auth::user();

        // return JWT token which sanctum generated.
        // store token into cookie is a better solution than just send token to the fron-end.
        $token = $user->createToken('korisnikov-token')->plainTextToken;
        $cookie = cookie('jwt', $token, 60*24); // one day
        return response([
            'message' => 'Success!'
        ])->withCookie($cookie);

        // napomena: Postaviti 'supports_credentials' => true, u config/cors.php
        // credentials su coockie ovom slucaju.

        
    }


    public function user()
    {
        return Auth::user();
    }
}
