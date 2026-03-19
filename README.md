# eduzz/miau-client

Client PHP para o serviço de autenticação Eduzz Miau.

## Instalação

```bash
composer require eduzz/miau-client
```

## Requisitos

- PHP >= 8.3
- Extensão APCu (para cache de tokens entre requisições)

## Uso

```php
use Eduzz\Miau\MiauClient;

$client = new MiauClient('https://your-miau-api-url', 'your-app-secret');

$token = $client->getToken();
```

## Exemplo

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

## Middleware Laravel

O pacote inclui um middleware compatível com Laravel que autentica requisições usando tokens Miau e verifica permissões automaticamente.

### Registrar o middleware

No seu `app/Http/Kernel.php`:

```php
use Eduzz\Miau\MiauClient;
use Eduzz\Miau\Middleware\MiauMiddleware;

// No array $routeMiddleware:
protected $routeMiddleware = [
    // ...
    'miau' => MiauMiddleware::class,
];
```

Registre o `MiauMiddleware` no seu service provider para que o Laravel possa injetá-lo:

```php
// No AppServiceProvider ou em um provider dedicado
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

### Uso nas rotas

```php
Route::middleware('miau')->group(function () {
    Route::get('/your/endpoint', function (Request $request) {
        // $request->miauApplication  - ['id' => '...', 'name' => '...']
        // $request->miauMetadata     - metadata de permissão
        return response()->json(['app' => $request->miauApplication]);
    });
});
```

### Handler de fallback

O middleware aciona o fallback quando o token está ausente ou não é um token Miau válido (erros HTTP 400). Isso permite lidar com esquemas de autenticação alternativos nas mesmas rotas -- por exemplo, aceitar Basic Auth para clients legados enquanto ainda suporta tokens Miau.

```php
use Eduzz\Miau\MiauClient;
use Eduzz\Miau\Middleware\MiauMiddleware;
use Illuminate\Http\JsonResponse;

// Registrar uma instância do middleware com fallback de Basic Auth
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
                'message' => 'Credenciais não fornecidas',
            ], 401);
        }

        $decoded = base64_decode(substr($authHeader, 6));
        [$username, $password] = explode(':', $decoded, 2);

        // Valide as credenciais com sua própria lógica
        if (!$this->validateCredentials($username, $password)) {
            return new JsonResponse([
                'error' => 'Unauthorized',
                'message' => 'Credenciais inválidas',
            ], 401);
        }

        $request->attributes->set('username', $username);

        return $next($request);
    };

    return new MiauMiddleware($client, $basicAuthFallback);
});
```

Depois aplique nas rotas que devem aceitar tanto tokens Miau quanto Basic Auth:

```php
Route::middleware('miau.basic')->group(function () {
    Route::get('/legacy-route', function (Request $request) {
        $miauApp = $request->attributes->get('miauApplication');

        if ($miauApp) {
            // Autenticado via token Miau
            return response()->json([
                'auth' => 'miau',
                'application' => $miauApp,
            ]);
        }

        // Autenticado via fallback Basic Auth
        return response()->json([
            'auth' => 'basic',
            'username' => $request->attributes->get('username'),
        ]);
    });
});
```
