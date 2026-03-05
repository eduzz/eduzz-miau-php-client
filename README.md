# eduzz/miau-client

PHP client for the Eduzz Miau authentication service.

## Installation

```bash
composer require eduzz/miau-client
```

## Requirements

- PHP >= 7.3
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
