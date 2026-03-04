<?php

declare(strict_types=1);

namespace Eduzz\Miau;

use GuzzleHttp\Client;
use Firebase\JWT\JWT;

class MiauClient
{
    private string $apiUrl;
    private string $basicAuthToken;
    private string $cacheKey;
    private Client $http;

    public function __construct(string $apiUrl, string $appSecret, float $timeout = 10.0)
    {
        if (empty($apiUrl) || empty($appSecret)) {
            throw new \InvalidArgumentException(
                'Invalid MiauClient configuration. Please provide apiUrl and appSecret.'
            );
        }

        $this->apiUrl = $apiUrl;
        $this->cacheKey = 'miau_token:' . md5($apiUrl);
        $this->http = new Client(['timeout' => $timeout]);

        $apiKey = substr($appSecret, 7, 25);
        $hashedSecret = hash('sha256', $appSecret);
        $this->basicAuthToken = base64_encode("{$apiKey}:{$hashedSecret}");
    }

    public function getToken(): string
    {
        $cached = apcu_fetch($this->cacheKey, $success);

        if ($success && is_string($cached)) {
            $decoded = $this->decodeTokenPayload($cached);
            $oneMinuteFromNow = time() + 60;

            if ($decoded['exp'] > $oneMinuteFromNow) {
                return $cached;
            }
        }

        $response = $this->http->request('GET', "{$this->apiUrl}/v1/oauth/token", [
            'headers' => [
                'Authorization' => "Basic {$this->basicAuthToken}",
                'Content-Type' => 'application/json',
            ],
            'http_errors' => false,
        ]);

        $data = json_decode((string) $response->getBody(), true);

        if ($response->getStatusCode() !== 200) {
            $errorMessage = $data['message']
                ?? $data['error_description']
                ?? ('OAuth error: ' . ($data['error'] ?? ''))
                ?? 'Failed to fetch JWT token';

            throw new \RuntimeException($errorMessage);
        }

        $token = $data['access_token'];

        $decoded = $this->decodeTokenPayload($token);
        $ttl = max(0, $decoded['exp'] - time() - 60);
        apcu_store($this->cacheKey, $token, $ttl);

        return $token;
    }

    private function decodeTokenPayload(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid JWT token format.');
        }

        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);

        if (!is_array($payload) || !isset($payload['exp'])) {
            throw new \RuntimeException('Invalid JWT token payload.');
        }

        return $payload;
    }
}

