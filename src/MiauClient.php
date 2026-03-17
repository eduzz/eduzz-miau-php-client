<?php

declare(strict_types=1);

namespace Eduzz\Miau;

use CoderCat\JWKToPEM\JWKConverter;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Client;

class MiauClient
{
    private $apiUrl;
    private $appSecret;
    private $basicAuthToken;
    private $tokenCacheKey;
    private $http;

    public function __construct(string $apiUrl, string $appSecret, float $timeout = 10.0)
    {
        if (empty($apiUrl) || empty($appSecret)) {
            throw new \InvalidArgumentException(
                'Invalid MiauClient configuration. Please provide apiUrl and appSecret.'
            );
        }

        $this->apiUrl = $apiUrl;
        $this->appSecret = $appSecret;
        $this->tokenCacheKey = 'miau_token:' . md5($apiUrl);
        $this->http = new Client(['timeout' => $timeout]);

        $apiKey = substr($appSecret, 7, 25);
        $hashedSecret = hash('sha256', $appSecret);
        $this->basicAuthToken = base64_encode("{$apiKey}:{$hashedSecret}");
    }

    public function getEnvironment(): string
    {
        $envChar = substr($this->appSecret, 5, 1);
        $environment = Constants::INVERSE_ENV_MAP[$envChar] ?? null;

        if (!$environment) {
            throw new \RuntimeException('Invalid environment in appSecret.');
        }

        return $environment;
    }

    public function getToken(): string
    {
        $cached = apcu_fetch($this->tokenCacheKey, $success);

        if ($success && is_string($cached)) {
            $payload = $this->decodeToken($cached);
            $oneMinuteFromNow = time() + 60;

            if ($payload['exp'] > $oneMinuteFromNow) {
                return $cached;
            }
        }

        $response = $this->http->request('GET', $this->getOAuthTokenUrl(), [
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

        $payload = $this->decodeToken($token);
        $ttl = max(0, $payload['exp'] - time() - 60);
        apcu_store($this->tokenCacheKey, $token, $ttl);

        return $token;
    }

    public function getTokenData(): array
    {
        $token = $this->getToken();
        return $this->decodeToken($token);
    }

    public function getPublicKey(string $kid): string
    {
        $cacheKey = "miau_jwks:{$kid}";
        $cached = apcu_fetch($cacheKey, $success);

        if ($success && is_string($cached)) {
            return $cached;
        }

        $response = $this->http->request('GET', $this->getJwksUrl(), [
            'headers' => ['Content-Type' => 'application/json'],
            'http_errors' => false,
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new \RuntimeException('Failed to fetch JWKS.');
        }

        $data = json_decode((string) $response->getBody(), true);
        $keys = $data['keys'] ?? [];

        $matchedKey = null;
        foreach ($keys as $key) {
            if (($key['kid'] ?? '') === $kid) {
                $matchedKey = $key;
                break;
            }
        }

        if (!$matchedKey) {
            throw new \RuntimeException("Key with kid '{$kid}' not found in JWKS.");
        }

        $jwkConverter = new JWKConverter();
        $pem = $jwkConverter->toPEM($matchedKey);
        apcu_store($cacheKey, $pem, 3600);

        return $pem;
    }

    public function verify(string $token, string $publicKey): \stdClass
    {
        return JWT::decode($token, new Key($publicKey, 'RS256'));
    }

    public function hasPermission(string $sourceAppId, array $resource): array
    {
        $body = json_encode(['sourceAppId' => $sourceAppId, 'resource' => $resource]);
        $cacheKey = 'miau_perm:' . md5($body);

        $cached = apcu_fetch($cacheKey, $success);

        if ($success && is_array($cached)) {
            return $cached;
        }

        $response = $this->http->request('POST', $this->getHasPermissionUrl(), [
            'headers' => [
                'Authorization' => "Basic {$this->basicAuthToken}",
                'Content-Type' => 'application/json',
            ],
            'body' => $body,
            'http_errors' => false,
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new \RuntimeException('Failed to check permission.');
        }

        $data = json_decode((string) $response->getBody(), true);

        $expires = $response->getHeaderLine('Expires');
        $ttl = $expires ? max(0, strtotime($expires) - time()) : 60;
        apcu_store($cacheKey, $data, $ttl);

        return $data;
    }

    public function decodeToken(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid JWT token format.');
        }

        return json_decode(JWT::urlsafeB64Decode($parts[1]), true);
    }

    private function getJwksUrl(): string
    {
        return "{$this->apiUrl}/v1/jwks.json";
    }

    private function getHasPermissionUrl(): string
    {
        return "{$this->apiUrl}/v1/has-permission";
    }

    private function getOAuthTokenUrl(): string
    {
        return "{$this->apiUrl}/v1/oauth/token";
    }

}
