<?php

declare(strict_types=1);

namespace Eduzz\Miau;

class HttpError extends \RuntimeException
{
    private $statusCode;
    private $errorName;
    private $errorCode;

    public function __construct(int $statusCode, string $errorName, string $message, string $errorCode)
    {
        parent::__construct("{$message} ({$errorCode})");
        $this->statusCode = $statusCode;
        $this->errorName = $errorName;
        $this->errorCode = $errorCode;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    public function getErrorName(): string
    {
        return $this->errorName;
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }
}
