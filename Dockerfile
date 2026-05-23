FROM 6.3-php8.2-fpm-alpine
RUN apk add --no-cache pcre-dev $PHPIZE_DEPS \
&& pecl install igbinary \
&& docker-php-ext-enable igbinary \
&& pecl install redis \
&& docker-php-ext-enable redis