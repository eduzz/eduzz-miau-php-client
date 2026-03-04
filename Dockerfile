FROM php:8.3-cli

RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/* \
    && pecl install apcu && docker-php-ext-enable apcu \
    && echo "apc.enable_cli=1" >> /usr/local/etc/php/conf.d/docker-php-ext-apcu.ini

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

RUN composer install --no-interaction

WORKDIR /app
