<?php

declare(strict_types=1);

namespace Eduzz\Miau;

class Constants
{
    const ISSUERS = [
        'development' => 'https://miau.devopzz.ninja',
        'test' => 'https://miau.testzz.ninja',
        'production' => 'https://miau.eduzz.com',
    ];

    const INVERSE_ENV_MAP = [
        'd' => 'development',
        'q' => 'test',
        'p' => 'production',
    ];
}
