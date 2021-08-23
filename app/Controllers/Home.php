<?php

namespace App\Controllers;

use App\Controllers\Auth;
use \Firebase\JWT\JWT;
use CodeIgniter\RESTful\ResourceController;

header('Access-Control-Allow-Origin : * ');
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Max-Age: 3600');
header('Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With');

class Home extends ResourceController
{
	public function __construct()
	{
		$this->protect = new Auth();
	}
	public function index()
	{
		$secret_key = $this->protect->privateKey();
		$token = NULL;
		$authHeader = $this->request->getServer('HTTP_AUTHORIZATION');
		$arr = explode(' ', $authHeader);

		$token = $arr[1];
		if ($token) {

			try {
				$decode = JWT::decode($token, $secret_key, array('HS256'));

				if ($decode) {
					$output = [
						'status' => 200,
						'message' => 'Akses diizinkan.'
					];
					return $this->respond($output, 200);
				}
			} catch (\Exception $e) {
				$output = [
					'status' => 403,
					'message' => 'Akses ditolak.',
					'error' => $e->getMessage()
				];
				return $this->respond($output, 403);
			}
		}
	}
}
