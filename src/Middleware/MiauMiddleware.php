<?php

declare(strict_types=1);

namespace Eduzz\Miau\Middleware;

use Closure;
use Eduzz\Miau\Constants;
use Eduzz\Miau\HttpError;
use Eduzz\Miau\MiauClient;
use Illuminate\Http\JsonResponse;

class MiauMiddleware
{
    private $client;
    private $fallback;

    public function __construct(MiauClient $client, callable $fallback = null)
    {
        $this->client = $client;
        $this->fallback = $fallback;
    }

    public function handle($request, Closure $next)
    {
        try {
            list($miauApplication, $miauMetadata) = $this->authenticate($request);

            $request->attributes->set('miauApplication', $miauApplication);
            $request->attributes->set('miauMetadata', $miauMetadata);

            return $next($request);
        } catch (HttpError $e) {
            if ($e->getStatusCode() === 400 && $this->fallback) {
                return call_user_func($this->fallback, $request, $next);
            }

            return new JsonResponse([
                'error' => $e->getErrorName(),
                'message' => $e->getMessage(),
            ], $e->getStatusCode());
        } catch (\Throwable $e) {
            $status = method_exists($e, 'getStatusCode') ? $e->getStatusCode() : 403;
            return new JsonResponse([
                'error' => (new \ReflectionClass($e))->getShortName(),
                'message' => $e->getMessage(),
            ], $status);
        }
    }

    private function authenticate($request): array
    {
        $authHeader = $request->header('Authorization', '');
        $parts = explode(' ', $authHeader);
        $token = end($parts) ?: '';

        if (empty($token)) {
            throw new HttpError(400, 'Invalid Token', 'Token not provided', 'MIAU_TKN_A');
        }

        try {
            $payload = $this->client->decodeToken($token);
            $header = json_decode(base64_decode(explode('.', $token)[0]), true);
        } catch (\Throwable $e) {
            throw new HttpError(400, 'Invalid Token', 'Token could not be decoded', 'MIAU_TKN_B');
        }

        $kid = $header['kid'] ?? null;
        if (empty($kid)) {
            throw new HttpError(400, 'Invalid Token', 'Missing kid in token header', 'MIAU_TKN_C');
        }

        $issuer = $payload['iss'] ?? '';
        if ($issuer !== Constants::ISSUERS['production']) {
            throw new HttpError(400, 'Invalid Token', 'Token issuer is invalid', 'MIAU_TKN_D');
        }

        $publicKey = $this->client->getPublicKey($kid);
        $clientTokenData = $this->client->verify($token, $publicKey);
        $serverTokenData = $this->client->getTokenData();

        $clientApp = $clientTokenData->application ?? null;
        $clientSecret = $clientTokenData->secret ?? null;

        if (
            !$clientApp
            || !$clientSecret
            || empty($clientApp->id)
            || empty($clientSecret->id)
            || empty($clientSecret->environment)
        ) {
            throw new HttpError(401, 'Invalid Token', 'Token invalid or expired', 'MIAU_TKN_E');
        }

        $serverSecret = $serverTokenData['secret'] ?? [];

        if ($clientSecret->environment !== ($serverSecret['environment'] ?? '')) {
            throw new HttpError(
                401,
                'Invalid Environment',
                "Secret environment {$clientSecret->environment} does not match Server environment {$serverSecret['environment']}",
                'MIAU_ENV_A'
            );
        }

        $resource = [
            'protocol' => 'http',
            'method' => $request->method(),
            'path' => '/' . ltrim($request->path(), '/'),
        ];

        $permissionResult = $this->client->hasPermission($clientApp->id, $resource);

        if (empty($permissionResult['success'])) {
            $serverApp = $serverTokenData['application'] ?? [];
            throw new HttpError(
                403,
                'Forbidden',
                "{$clientApp->name} does not have permission to {$request->method()} {$request->path()} on {$serverApp['name']}",
                'MIAU_PERM_B'
            );
        }

        $miauApplication = ['id' => $clientApp->id, 'name' => $clientApp->name];
        $miauMetadata = $permissionResult['metadata'] ?? [];

        return [$miauApplication, $miauMetadata];
    }
}
