# eduzz/miau-client

PHP client for the Eduzz Miau authentication service.

## Installation

```bash
composer require eduzz/miau-client
```

## Requirements

- PHP >= 8.3
- APCu extension (for token caching across requests)

## Usage

```php
use Eduzz\Miau\MiauClient;

$client = new MiauClient('https://your-miau-api-url', 'your-app-secret');

$token = $client->getToken();
```

## Example

```php
use Eduzz\Miau\MiauClient;
use GuzzleHttp\Client;

$miauApiUrl = getenv('MIAU_API_URL');
$miauAppSecret = getenv('MIAU_APP_SECRET') ?: '';
$yourApiUrl = getenv('YOUR_API_URL') ?: 'https://your-api.example.com';

$miau = new MiauClient($miauApiUrl, $miauAppSecret);
$token = $miau->getToken();

$http = new Client();
$response = $http->get("{$yourApiUrl}/your/endpoint", [
    'headers' => [
        'Authorization' => "Bearer {$token}",
    ],
]);

$data = json_decode((string) $response->getBody(), true);
echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . PHP_EOL;
```

## API

### `new MiauClient(string $apiUrl, string $appSecret, float $timeout = 10.0)`

Creates a new client instance.

| Parameter    | Type     | Default | Description                  |
|-------------|----------|---------|------------------------------|
| `$apiUrl`   | `string` | —       | Miau API base URL            |
| `$appSecret`| `string` | —       | Application secret from Miau |
| `$timeout`  | `float`  | `10.0`  | HTTP request timeout in seconds |

### `$client->getToken(): string`

Returns a valid JWT access token. Tokens are cached via APCu and automatically refreshed when they are within 60 seconds of expiration.

### `$client->getTokenData(): array`

Returns the decoded payload of the server's own token.

### `$client->getEnvironment(): string`

Returns the environment extracted from the app secret (`development`, `test`, or `production`).

### `$client->getPublicKey(string $kid): string`

Fetches and caches the public key for the given key ID from the JWKS endpoint.

### `$client->verify(string $token, string $publicKey): array`

Verifies a JWT token signature using the provided RSA public key (RS256). Returns the decoded payload.

### `$client->hasPermission(string $sourceAppId, array $resource): array`

Checks if a source application has permission to access a given resource. Results are cached via APCu.

### `$client->decodeToken(string $token): array`

Decodes the JWT and returns the payload as an associative array.

## Laravel Middleware

The package includes a Laravel-compatible middleware that authenticates incoming requests using Miau tokens and checks permissions automatically.

### Register the middleware

In your `app/Http/Kernel.php`:

```php
use Eduzz\Miau\MiauClient;
use Eduzz\Miau\Middleware\MiauMiddleware;

// In the $routeMiddleware array:
protected $routeMiddleware = [
    // ...
    'miau' => MiauMiddleware::class,
];
```

Register the `MiauMiddleware` in your service provider so Laravel can inject it:

```php
// In AppServiceProvider or a dedicated provider
use Eduzz\Miau\MiauClient;
use Eduzz\Miau\Middleware\MiauMiddleware;

public function register()
{
    $this->app->singleton(MiauMiddleware::class, function () {
        $client = new MiauClient(
            config('services.miau.api_url'),
            config('services.miau.app_secret')
        );

        return new MiauMiddleware($client);
    });
}
```

### Use in routes

```php
Route::middleware('miau')->group(function () {
    Route::get('/your/endpoint', function (Request $request) {
        // $request->miauApplication  - ['id' => '...', 'name' => '...']
        // $request->miauMetadata     - permission metadata
        return response()->json(['app' => $request->miauApplication]);
    });
});
```

### Fallback handler

You can provide a fallback callable for requests with missing or malformed tokens (400 errors). This is useful when some routes should allow unauthenticated access:

```php
$this->app->singleton(MiauMiddleware::class, function () {
    $client = new MiauClient(
        config('services.miau.api_url'),
        config('services.miau.app_secret')
    );

    return new MiauMiddleware($client, function ($request, $next) {
        return $next($request);
    });
});
```

## Token Caching

This client uses APCu to cache tokens across PHP requests. Make sure APCu is installed and enabled:

```ini
; php.ini
extension=apcu
apc.enabled=1
```

For CLI usage (e.g. workers, scripts), also enable:

```ini
apc.enable_cli=1
```
