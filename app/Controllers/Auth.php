<?php

namespace App\Controllers;

use App\Models\Auth_model;
use CodeIgniter\RESTful\ResourceController;
use \Firebase\JWT\JWT;

class Auth extends ResourceController
{
    public function __construct()
    {
        $this->Auth_model = new Auth_model();
    }

    public function privateKey()
    {
        $privateKey = <<<EOD
        -----BEGIN RSA PRIVATE KEY-----
        MIICXAIBAAKBgQC8kGa1pSjbSYZVebtTRBLxBz5H4i2p/llLCrEeQhta5kaQu/Rn
        vuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t0tyazyZ8JXw+KgXTxldMPEL9
        5+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4ehde/zUxo6UvS7UrBQIDAQAB
        AoGAb/MXV46XxCFRxNuB8LyAtmLDgi/xRnTAlMHjSACddwkyKem8//8eZtw9fzxz
        bWZ/1/doQOuHBGYZU8aDzzj59FZ78dyzNFoF91hbvZKkg+6wGyd/LrGVEB+Xre0J
        Nil0GReM2AHDNZUYRv+HYJPIOrB0CRczLQsgFJ8K6aAD6F0CQQDzbpjYdx10qgK1
        cP59UHiHjPZYC0loEsk7s+hUmT3QHerAQJMZWC11Qrn2N+ybwwNblDKv+s5qgMQ5
        5tNoQ9IfAkEAxkyffU6ythpg/H0Ixe1I2rd0GbF05biIzO/i77Det3n4YsJVlDck
        ZkcvY3SK2iRIL4c9yY6hlIhs+K9wXTtGWwJBAO9Dskl48mO7woPR9uD22jDpNSwe
        k90OMepTjzSvlhjbfuPN1IdhqvSJTDychRwn1kIJ7LQZgQ8fVz9OCFZ/6qMCQGOb
        qaGwHmUK6xzpUbbacnYrIM6nLSkXgOAwv7XXCojvY614ILTK3iXiLBOxPu5Eu13k
        eUz9sHyD6vkgZzjtxXECQAkp4Xerf5TGfQXGXhxIX52yH+N2LtujCdkQZjXAsGdm
        B2zNzvrlgRmgBrklMTrMYgm1NPcW+bRLGcwgW2PTvNM=
        -----END RSA PRIVATE KEY-----
        EOD;
        return $privateKey;
    }

    public function login()
    {
        $email = $this->request->getVar('email');
        $password = $this->request->getVar('password');

        $cekLogin = $this->Auth_model->cekLogin($email);

        if (password_verify($password, $cekLogin['password'])) {
            $secret_key = $this->privateKey();
            $issuer_claim = 'THE_CLAIM';
            $audience_claim = 'THE_AUDIENCE';
            $issudat_claim = time();
            $notbefore_claim = $issudat_claim + 10;
            $expire_claim = $issudat_claim + 3600;

            $token = [
                'iss' => $issuer_claim,
                'aud' => $audience_claim,
                'iat' => $issudat_claim,
                'nbf' => $notbefore_claim,
                'exp' => $expire_claim,
                'data' => [
                    'id' => $cekLogin['id'],
                    'nama' => $cekLogin['nama'],
                    'email' => $cekLogin['email'],
                    'password' => $cekLogin['password'],
                ],
            ];
            $token = JWT::encode($token, $secret_key);

            $output = [
                'status' => 200,
                'message' => 'Login berhasil.',
                'token' => $token,
                'expireAt' => $expire_claim
            ];
            return $this->respond($output, 200);
        } else {
            $output = [
                'status' => 403,
                'message' => 'Login gagal.'
            ];
            return $this->respond($output, 403);
        }
    }

    public function register()
    {
        $nama = $this->request->getVar('nama');
        $email = $this->request->getVar('email');
        $password = $this->request->getVar('password');

        $password_hash = password_hash($password, PASSWORD_BCRYPT);

        $data = [
            'nama' => $nama,
            'email' => $email,
            'password' => $password_hash
        ];
        $register = $this->Auth_model->register($data);
        if ($register == true) {
            $output = [
                'status' => 200,
                'message' => 'Register berhasil.'
            ];
            return $this->respond($output, 200);
        } else {
            $output = [
                'status' => 403,
                'message' => 'Register gagal.'
            ];
            return $this->respond($output, 403);
        }
    }
}
