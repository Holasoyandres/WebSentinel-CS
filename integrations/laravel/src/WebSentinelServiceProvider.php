<?php

namespace WebSentinel;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use WebSentinel\Http\Middleware\WebSentinelFirewall;
use WebSentinel\Http\Middleware\WebSentinelTrackActivity;
use WebSentinel\Listeners\AuthFailedListener;
use WebSentinel\Listeners\AuthLoginListener;
use WebSentinel\Listeners\AuthLogoutListener;
use WebSentinel\Services\SentinelClient;
use WebSentinel\View\Components\Honeypot;

class WebSentinelServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/websentinel.php', 'websentinel');

        $this->app->singleton(SentinelClient::class, function () {
            return new SentinelClient();
        });

        $this->app->singleton(WebSentinelFirewall::class, function ($app) {
            return new WebSentinelFirewall($app->make(SentinelClient::class));
        });

        $this->app->singleton(WebSentinelTrackActivity::class, function ($app) {
            return new WebSentinelTrackActivity($app->make(SentinelClient::class));
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // 1. Publish Configuration
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/websentinel.php' => config_path('websentinel.php'),
            ], 'websentinel-config');
        }

        // 2. Register Blade Honeypot Directives & Components
        if (class_exists(Blade::class)) {
            Blade::directive('websentinelHoneypot', function () {
                return '<?php echo \WebSentinel\View\Components\Honeypot::renderHtml(); ?>';
            });

            Blade::component('websentinel-honeypot', function () {
                return Honeypot::renderHtml();
            });
        }

        // 3. Register Automatic Auth Event Listeners (SOC Session Feeder)
        if (class_exists(Event::class)) {
            Event::listen(Login::class, AuthLoginListener::class);
            Event::listen(Failed::class, AuthFailedListener::class);
            Event::listen(Logout::class, AuthLogoutListener::class);
        }

        // 4. Register Router Middleware Aliases if Router Available
        $router = $this->app['router'] ?? null;
        if ($router && method_exists($router, 'aliasMiddleware')) {
            $router->aliasMiddleware('websentinel.firewall', WebSentinelFirewall::class);
            $router->aliasMiddleware('websentinel.track', WebSentinelTrackActivity::class);
        }
    }
}
