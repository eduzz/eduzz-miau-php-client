<?php

declare(strict_types=1);

namespace Eduzz\Miau;

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
        apcu_store($this->tokenCacheKey, $token, $ttl);

        return $token;
    }

    public function getTokenData(): array
    {
        $token = $this->getToken();
        return $this->decodeTokenPayload($token);
    }

    public function getPublicKey(string $kid): string
    {
        $cacheKey = "miau_jwks:{$kid}";
        $cached = apcu_fetch($cacheKey, $success);

        if ($success && is_string($cached)) {
            return $cached;
        }

        $response = $this->http->request('GET', "{$this->apiUrl}/v1/jwks.json", [
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

        $pem = $this->jwkToPem($matchedKey);
        apcu_store($cacheKey, $pem, 3600);

        return $pem;
    }

    public function verify(string $token, string $publicKey): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid JWT token format.');
        }

        $signatureInput = "{$parts[0]}.{$parts[1]}";
        $signature = base64_decode(strtr($parts[2], '-_', '+/'));

        $pubKeyResource = openssl_pkey_get_public($publicKey);

        if ($pubKeyResource === false) {
            throw new \RuntimeException('Invalid public key.');
        }

        $result = openssl_verify($signatureInput, $signature, $pubKeyResource, OPENSSL_ALGO_SHA256);

        if ($result !== 1) {
            throw new \RuntimeException('Token signature verification failed.');
        }

        return $this->decodeTokenPayload($token);
    }

    public function hasPermission(string $sourceAppId, array $resource): array
    {
        $body = json_encode(['sourceAppId' => $sourceAppId, 'resource' => $resource]);
        $cacheKey = 'miau_perm:' . md5($body);

        $cached = apcu_fetch($cacheKey, $success);

        if ($success && is_array($cached)) {
            return $cached;
        }

        $response = $this->http->request('POST', "{$this->apiUrl}/v1/has-permission", [
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

    public function decodeTokenHeader(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid JWT token format.');
        }

        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);

        if (!is_array($header)) {
            throw new \RuntimeException('Invalid JWT token header.');
        }

        return $header;
    }

    public function decodeTokenPayload(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid JWT token format.');
        }

        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);

        if (!is_array($payload)) {
            throw new \RuntimeException('Invalid JWT token payload.');
        }

        return $payload;
    }

    private function jwkToPem(array $jwk): string
    {
        if (($jwk['kty'] ?? '') !== 'RSA') {
            throw new \RuntimeException('Only RSA keys are supported.');
        }

        $n = $this->base64UrlDecode($jwk['n']);
        $e = $this->base64UrlDecode($jwk['e']);

        $modulus = pack('Ca*a*', 2, $this->encodeLength(strlen($n)) . $n, '');
        $modulus = "\x00" . $n;
        $modulus = "\x02" . $this->encodeLength(strlen($modulus)) . $modulus;

        $exponent = "\x02" . $this->encodeLength(strlen($e)) . $e;

        $sequence = $modulus . $exponent;
        $sequence = "\x30" . $this->encodeLength(strlen($sequence)) . $sequence;

        $bitString = "\x00" . $sequence;
        $bitString = "\x03" . $this->encodeLength(strlen($bitString)) . $bitString;

        $rsaOid = pack('H*', '300d06092a864886f70d0101010500');
        $publicKey = $rsaOid . $bitString;
        $publicKey = "\x30" . $this->encodeLength(strlen($publicKey)) . $publicKey;

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($publicKey), 64, "\n")
            . "-----END PUBLIC KEY-----";
    }

    private function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function encodeLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), "\x00");
        return chr(0x80 | strlen($temp)) . $temp;
    }
}
