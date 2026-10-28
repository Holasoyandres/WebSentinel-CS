<?php

namespace WebSentinel;

use Illuminate\Support\ServiceProvider;
use WebSentinel\Services\SentinelClient;

class WebSentinelServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/websentinel.php', 'websentinel');

        $this->app->singleton(SentinelClient::class, function ($app) {
            return new SentinelClient();
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/websentinel.php' => config_path('websentinel.php'),
            ], 'websentinel-config');
        }
    }
}
