<?php

namespace App\Controllers\Api;

use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\RESTful\ResourceController;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;

class AuthController extends ResourceController
{

    // Register endpoint
    public function register()
    {
        // Add users into application
        $rules = [
            'username' => 'required|is_unique[users.username]',
            'email' => 'required|is_unique[auth_identities.secret]',
            'password' => 'required',
        ];

        if (!$this->validate($rules)) {
            return $this->respond($this->arrayResponse(
                ResponseInterface::HTTP_INTERNAL_SERVER_ERROR,
                $this->validator->getErrors(),
                true,
                [],
            ), ResponseInterface::HTTP_INTERNAL_SERVER_ERROR);
        }

        $userObject = new UserModel();
        $user = new User([
            'username' => $this->request->getVar('username'),
            'email' => $this->request->getVar('email'),
            'password' => $this->request->getVar('password'),
        ]);

        $userObject->save($user);

        return $this->respond($this->stringResponse(
            ResponseInterface::HTTP_OK,
            'User created successfully',
            false,
            []
        ), ResponseInterface::HTTP_OK);
    }

    // Login endpoint
    public function login()
    {
        // Handle user login and also generate token

        if (auth()->loggedIn()) {
            auth()->logout();
        }

        $rules = [
            'email' => 'required',
            'password' => 'required',
        ];

        if (!$this->validate($rules)) {
            return $this->respond($this->arrayResponse(
                ResponseInterface::HTTP_INTERNAL_SERVER_ERROR,
                $this->validator->getErrors(),
                true,
                [],
            ), ResponseInterface::HTTP_INTERNAL_SERVER_ERROR);
        }

        $credential = [
            'email' => $this->request->getVar('email'),
            'password' => $this->request->getVar('password'),
        ];

        $loginAttempt = auth()->attempt($credential);
        if (!$loginAttempt->isOK()) {
            return $this->respond($this->stringResponse(
                ResponseInterface::HTTP_INTERNAL_SERVER_ERROR,
                'Invalid Credentials',
                true,
                [],
            ), ResponseInterface::HTTP_INTERNAL_SERVER_ERROR);
        }

        $userObject = new UserModel();
        $user_data = $userObject->findById(auth()->id());
        $token = $user_data->generateAccessToken("Api Shield");
        $auth_token = $token->raw_token;

        return $this->respond($this->stringResponse(
            ResponseInterface::HTTP_OK,
            'User logged in',
            false,
            [
                'token' => $auth_token
            ]
        ), ResponseInterface::HTTP_OK);
    }

    // Profile endpoint
    public function profile()
    {
        // Get logged is user info

        if (auth('tokens')->loggedIn()) {
            $userId = auth()->id();

            $userObject = new UserModel();
            $user_data = $userObject->findById($userId);

            return $this->respond($this->stringResponse(
                ResponseInterface::HTTP_OK,
                'User logged in',
                false,
                [
                    'user' => $user_data
                ]
            ), ResponseInterface::HTTP_OK);
        }
    }

    // Logout endpoint
    public function logout()
    {
        // Handle user logout, destroy token
        if (auth('tokens')->loggedIn()) {
            auth()->logout();
            auth()->user()->revokeAllAccessTokens();

            return $this->respond($this->stringResponse(
                ResponseInterface::HTTP_OK,
                'User logged out successfully',
                false,
                []
            ), ResponseInterface::HTTP_OK);
        }
    }

    // Invalid endpoint
    public function invalidRequest()
    {
        return $this->respond($this->stringResponse(
            ResponseInterface::HTTP_FORBIDDEN,
            'Invalid request, please login',
            true,
            [],
        ), ResponseInterface::HTTP_FORBIDDEN);
    }

    private function arrayResponse(int $status, array $message, bool $error, array $data)
    {
        return [
            'status' => $status,
            'message' => $message,
            'error' => $error,
            'data' => $data,
        ];
    }

    private function stringResponse(int $status, string $message, bool $error, array $data)
    {
        return [
            'status' => $status,
            'message' => $message,
            'error' => $error,
            'data' => $data,
        ];
    }
}
