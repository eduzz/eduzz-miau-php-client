<?php

declare(strict_types=1);

namespace Eduzz\Miau\Tests;

use Eduzz\Miau\Constants;
use Eduzz\Miau\MiauClient;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

class MiauClientTest extends TestCase
{
    private const API_URL = 'https://miau.test';
    private const APP_SECRET = 'miau_d_abcdefghijklmnopqrstuvwxyz0123456789';

    protected function setUp(): void
    {
        if (function_exists('apcu_clear_cache')) {
            apcu_clear_cache();
        }
    }

    private function makeJwt(int $exp, array $extraPayload = []): string
    {
        $header = $this->base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = $this->base64UrlEncode(json_encode(array_merge([
            'exp' => $exp,
            'iss' => Constants::ISSUERS['production'],
            'application' => ['id' => 'a1', 'name' => 'test'],
            'secret' => ['id' => 's1', 'environment' => 'development'],
        ], $extraPayload)));
        $signature = $this->base64UrlEncode('fake-signature');

        return "{$header}.{$payload}.{$signature}";
    }

    private function makeJwtWithKid(int $exp, string $kid): string
    {
        $header = $this->base64UrlEncode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid]));
        $payload = $this->base64UrlEncode(json_encode([
            'exp' => $exp,
            'iss' => Constants::ISSUERS['production'],
            'application' => ['id' => 'a1', 'name' => 'test'],
            'secret' => ['id' => 's1', 'environment' => 'development'],
        ]));
        $signature = $this->base64UrlEncode('fake-signature');

        return "{$header}.{$payload}.{$signature}";
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function createClientWithMock(array $responses, array &$history = []): MiauClient
    {
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($history));

        $httpClient = new Client(['handler' => $stack]);

        $client = new MiauClient(self::API_URL, self::APP_SECRET);

        $reflection = new \ReflectionClass($client);
        $prop = $reflection->getProperty('http');
        $prop->setAccessible(true);
        $prop->setValue($client, $httpClient);

        return $client;
    }

    // --- Constructor tests ---

    public function testThrowsOnEmptyApiUrl(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new MiauClient('', self::APP_SECRET);
    }

    public function testThrowsOnEmptyAppSecret(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new MiauClient(self::API_URL, '');
    }

    public function testBasicAuthTokenMatchesNodeLogic(): void
    {
        $client = new MiauClient(self::API_URL, self::APP_SECRET);

        $apiKey = substr(self::APP_SECRET, 7, 25);
        $hashed = hash('sha256', self::APP_SECRET);
        $expected = base64_encode("{$apiKey}:{$hashed}");

        $reflection = new \ReflectionClass($client);
        $prop = $reflection->getProperty('basicAuthToken');
        $prop->setAccessible(true);

        $this->assertSame($expected, $prop->getValue($client));
    }

    // --- getToken tests ---

    public function testFetchesTokenFromApi(): void
    {
        $token = $this->makeJwt(time() + 300);

        $client = $this->createClientWithMock([
            new Response(200, [], json_encode([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'expires_in' => 300,
            ])),
        ]);

        $this->assertSame($token, $client->getToken());
    }

    public function testCachesTokenBeforeExpiry(): void
    {
        $token = $this->makeJwt(time() + 300);
        $history = [];

        $client = $this->createClientWithMock([
            new Response(200, [], json_encode([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'expires_in' => 300,
            ])),
        ], $history);

        $client->getToken();
        $client->getToken();
        $client->getToken();

        $this->assertCount(1, $history);
    }

    public function testRefetchesTokenNearExpiry(): void
    {
        $expiredToken = $this->makeJwt(time() + 30);
        $freshToken = $this->makeJwt(time() + 300);
        $history = [];

        $client = $this->createClientWithMock([
            new Response(200, [], json_encode([
                'access_token' => $expiredToken,
                'token_type' => 'Bearer',
                'expires_in' => 30,
            ])),
            new Response(200, [], json_encode([
                'access_token' => $freshToken,
                'token_type' => 'Bearer',
                'expires_in' => 300,
            ])),
        ], $history);

        $first = $client->getToken();
        $second = $client->getToken();

        $this->assertCount(2, $history);
        $this->assertSame($expiredToken, $first);
        $this->assertSame($freshToken, $second);
    }

    public function testThrowsOnErrorResponse(): void
    {
        $client = $this->createClientWithMock([
            new Response(401, [], json_encode([
                'error' => 'invalid_client',
                'error_description' => 'Bad credentials',
            ])),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Bad credentials');
        $client->getToken();
    }

    public function testThrowsOnErrorWithMessageField(): void
    {
        $client = $this->createClientWithMock([
            new Response(403, [], json_encode([
                'message' => 'Forbidden access',
                'error' => 'forbidden',
            ])),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Forbidden access');
        $client->getToken();
    }

    public function testSendsCorrectAuthHeader(): void
    {
        $token = $this->makeJwt(time() + 300);
        $history = [];

        $client = $this->createClientWithMock([
            new Response(200, [], json_encode([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'expires_in' => 300,
            ])),
        ], $history);

        $client->getToken();

        $request = $history[0]['request'];
        $this->assertStringStartsWith('Basic ', $request->getHeaderLine('Authorization'));
        $this->assertSame('application/json', $request->getHeaderLine('Content-Type'));
    }

    // --- getEnvironment tests ---

    public function testGetEnvironmentDevelopment(): void
    {
        $client = new MiauClient(self::API_URL, 'miau_d_abcdefghijklmnopqrstuvwxyz0123456789');
        $this->assertSame('development', $client->getEnvironment());
    }

    public function testGetEnvironmentProduction(): void
    {
        $client = new MiauClient(self::API_URL, 'miau_p_abcdefghijklmnopqrstuvwxyz0123456789');
        $this->assertSame('production', $client->getEnvironment());
    }

    public function testGetEnvironmentTest(): void
    {
        $client = new MiauClient(self::API_URL, 'miau_q_abcdefghijklmnopqrstuvwxyz0123456789');
        $this->assertSame('test', $client->getEnvironment());
    }

    public function testGetEnvironmentInvalid(): void
    {
        $client = new MiauClient(self::API_URL, 'miau_x_abcdefghijklmnopqrstuvwxyz0123456789');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid environment');
        $client->getEnvironment();
    }

    // --- getTokenData tests ---

    public function testGetTokenDataReturnsDecodedPayload(): void
    {
        $token = $this->makeJwt(time() + 300);

        $client = $this->createClientWithMock([
            new Response(200, [], json_encode([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'expires_in' => 300,
            ])),
        ]);

        $data = $client->getTokenData();
        $this->assertSame('a1', $data['application']['id']);
        $this->assertSame('test', $data['application']['name']);
        $this->assertSame('s1', $data['secret']['id']);
        $this->assertSame('development', $data['secret']['environment']);
    }

    // --- getPublicKey tests ---

    public function testGetPublicKeyFetchesFromJwks(): void
    {
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($rsaKey);

        $jwks = [
            'keys' => [[
                'kty' => 'RSA',
                'kid' => 'test-kid',
                'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
                'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
            ]],
        ];

        $client = $this->createClientWithMock([
            new Response(200, [], json_encode($jwks)),
        ]);

        $pem = $client->getPublicKey('test-kid');
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $pem);

        $parsedKey = openssl_pkey_get_public($pem);
        $this->assertNotFalse($parsedKey);
    }

    public function testGetPublicKeyThrowsOnMissingKid(): void
    {
        $client = $this->createClientWithMock([
            new Response(200, [], json_encode(['keys' => []])),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Key with kid 'nonexistent' not found");
        $client->getPublicKey('nonexistent');
    }

    public function testGetPublicKeyCachesResult(): void
    {
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($rsaKey);

        $jwks = [
            'keys' => [[
                'kty' => 'RSA',
                'kid' => 'cached-kid',
                'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
                'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
            ]],
        ];

        $history = [];
        $client = $this->createClientWithMock([
            new Response(200, [], json_encode($jwks)),
        ], $history);

        $client->getPublicKey('cached-kid');
        $client->getPublicKey('cached-kid');

        $this->assertCount(1, $history);
    }

    // --- verify tests ---

    public function testVerifyValidSignature(): void
    {
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($rsaKey);
        $publicKeyPem = $details['key'];

        $header = $this->base64UrlEncode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'k1']));
        $payload = $this->base64UrlEncode(json_encode([
            'exp' => time() + 300,
            'application' => ['id' => 'a1', 'name' => 'test'],
            'secret' => ['id' => 's1', 'environment' => 'development'],
        ]));

        $signatureInput = "{$header}.{$payload}";
        openssl_sign($signatureInput, $signature, $rsaKey, OPENSSL_ALGO_SHA256);
        $encodedSignature = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');

        $token = "{$header}.{$payload}.{$encodedSignature}";

        $client = new MiauClient(self::API_URL, self::APP_SECRET);
        $result = $client->verify($token, $publicKeyPem);

        $this->assertSame('a1', $result->application->id);
    }

    public function testVerifyInvalidSignature(): void
    {
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($rsaKey);
        $publicKeyPem = $details['key'];

        $header = $this->base64UrlEncode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $payload = $this->base64UrlEncode(json_encode(['exp' => time() + 300]));
        $token = "{$header}.{$payload}.invalid-signature";

        $client = new MiauClient(self::API_URL, self::APP_SECRET);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('signature verification failed');
        $client->verify($token, $publicKeyPem);
    }

    // --- hasPermission tests ---

    public function testHasPermissionSuccess(): void
    {
        $client = $this->createClientWithMock([
            new Response(200, ['Expires' => gmdate('D, d M Y H:i:s', time() + 120) . ' GMT'], json_encode([
                'success' => true,
                'metadata' => ['role' => 'admin'],
            ])),
        ]);

        $result = $client->hasPermission('source-app', [
            'protocol' => 'http',
            'method' => 'GET',
            'path' => '/test',
        ]);

        $this->assertTrue($result['success']);
        $this->assertSame('admin', $result['metadata']['role']);
    }

    public function testHasPermissionCachesResult(): void
    {
        $history = [];
        $client = $this->createClientWithMock([
            new Response(200, ['Expires' => gmdate('D, d M Y H:i:s', time() + 120) . ' GMT'], json_encode([
                'success' => true,
                'metadata' => [],
            ])),
        ], $history);

        $resource = ['protocol' => 'http', 'method' => 'GET', 'path' => '/cached'];

        $client->hasPermission('app1', $resource);
        $client->hasPermission('app1', $resource);

        $this->assertCount(1, $history);
    }

    public function testHasPermissionThrowsOnError(): void
    {
        $client = $this->createClientWithMock([
            new Response(500, [], 'Server Error'),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to check permission');
        $client->hasPermission('app1', ['protocol' => 'http', 'method' => 'GET', 'path' => '/fail']);
    }
}
