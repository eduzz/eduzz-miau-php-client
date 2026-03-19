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

The middleware triggers the fallback when the incoming token is missing or not a valid Miau token (HTTP 400 errors). This lets you handle alternative authentication schemes on the same routes -- for example, accepting Basic Auth for legacy clients while still supporting Miau tokens.

```php
use Eduzz\Miau\MiauClient;
use Eduzz\Miau\Middleware\MiauMiddleware;
use Illuminate\Http\JsonResponse;

// Register a middleware instance with a Basic Auth fallback
$this->app->singleton('miau.basic', function () {
    $client = new MiauClient(
        config('services.miau.api_url'),
        config('services.miau.app_secret')
    );

    $basicAuthFallback = function ($request, $next) {
        $authHeader = $request->header('Authorization', '');

        if (empty($authHeader) || !str_starts_with($authHeader, 'Basic ')) {
            return new JsonResponse([
                'error' => 'Unauthorized',
                'message' => 'No credentials provided',
            ], 401);
        }

        $decoded = base64_decode(substr($authHeader, 6));
        [$username, $password] = explode(':', $decoded, 2);

        // Validate credentials against your own logic
        if (!$this->validateCredentials($username, $password)) {
            return new JsonResponse([
                'error' => 'Unauthorized',
                'message' => 'Invalid credentials',
            ], 401);
        }

        $request->attributes->set('username', $username);

        return $next($request);
    };

    return new MiauMiddleware($client, $basicAuthFallback);
});
```

Then apply it to routes that should accept both Miau tokens and Basic Auth:

```php
Route::middleware('miau.basic')->group(function () {
    Route::get('/legacy-route', function (Request $request) {
        $miauApp = $request->attributes->get('miauApplication');

        if ($miauApp) {
            // Authenticated via Miau token
            return response()->json([
                'auth' => 'miau',
                'application' => $miauApp,
            ]);
        }

        // Authenticated via Basic Auth fallback
        return response()->json([
            'auth' => 'basic',
            'username' => $request->attributes->get('username'),
        ]);
    });
});
```