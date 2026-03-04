<?php

declare(strict_types=1);

namespace Eduzz\Miau\Tests;

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

    private function makeJwt(int $exp): string
    {
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'exp' => $exp,
            'application' => ['id' => 'a1', 'name' => 'test'],
            'secret' => ['id' => 's1', 'environment' => 'development'],
        ]));
        $signature = base64_encode('fake-signature');

        return "{$header}.{$payload}.{$signature}";
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
}
