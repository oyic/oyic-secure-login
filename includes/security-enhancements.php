<?php
/**
 * Security Enhancements for OYIC Secure Login
 * 
 * Additional security features that complement the main plugin.
 * These features are automatically loaded when the plugin is active.
 * 
 * @package OYIC\SecureLogin
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Enhanced Security Features Class
 * 
 * Provides additional security measures beyond the core plugin functionality.
 * 
 * @since 1.0.0
 */
class OYIC_Security_Enhancements {

    /**
     * Initialize security enhancements
     * 
     * @since 1.0.0
     * @return void
     */
    public static function init() {
        // Get plugin options
        $options = get_option('oyic_secure_login_options', array());
        
        // Disable file editing in admin (if enabled in settings)
        if (!isset($options['disable_file_edit']) || $options['disable_file_edit']) {
            self::disable_file_editing();
        }
        
        // Disable XML-RPC (if enabled in settings)
        if (!isset($options['disable_xmlrpc']) || $options['disable_xmlrpc']) {
            add_filter('xmlrpc_enabled', '__return_false');
        }
        
        // Hide WordPress version (if enabled in settings)
        if (!isset($options['hide_wp_version']) || $options['hide_wp_version']) {
            remove_action('wp_head', 'wp_generator');
        }
        
        // Prevent user enumeration (if enabled in settings)
        if (!isset($options['prevent_user_enumeration']) || $options['prevent_user_enumeration']) {
            add_action('init', array(__CLASS__, 'prevent_user_enumeration'));
        }
        
        // Enhanced login attempt limiting (always enabled)
        add_action('wp_login_failed', array(__CLASS__, 'handle_login_failed'));
        add_action('wp_login', array(__CLASS__, 'handle_login_success'), 10, 2);
    }

    /**
     * Disable file editing in admin
     * 
     * @since 1.0.0
     * @return void
     */
    private static function disable_file_editing() {
        if (!defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
    }

    /**
     * Prevent user enumeration via ?author=1
     * 
     * @since 1.0.0
     * @return void
     */
    public static function prevent_user_enumeration() {
        if (!is_admin() && isset($_REQUEST['author'])) {
            // Log the attempt if logging is available
            if (function_exists('oyic_secure_login_log_event')) {
                oyic_secure_login_log_event('user_enumeration_attempt', 'User enumeration attempt blocked', array(
                    'author_param' => $_REQUEST['author'],
                    'ip' => oyic_secure_login_get_client_ip(),
                ));
            }
            
            wp_redirect(home_url());
            exit;
        }
    }

    /**
     * Handle failed login attempts with rate limiting
     * 
     * @since 1.0.0
     * @param string $username Username that failed login
     * @return void
     */
    public static function handle_login_failed($username) {
        $ip = oyic_secure_login_get_client_ip();
        $key = 'login_attempts_' . $ip;
        $attempts = (int) get_transient($key);
        $attempts++;
        set_transient($key, $attempts, 15 * MINUTE_IN_SECONDS);

        // Log the attempt if logging is available
        if (function_exists('oyic_secure_login_log_event')) {
            oyic_secure_login_log_event('login_failed', 'Failed login attempt', array(
                'username' => $username,
                'ip' => $ip,
                'attempts' => $attempts,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ));
        }

        if ($attempts >= 5) {
            // Log rate limit exceeded if logging is available
            if (function_exists('oyic_secure_login_log_event')) {
                oyic_secure_login_log_event('rate_limit_exceeded', 'Rate limit exceeded for IP', array(
                    'ip' => $ip,
                    'attempts' => $attempts,
                ));
            }
            
            wp_die(__('Too many login attempts. Try again later.', 'oyic-secure-login'));
        }
    }

    /**
     * Reset login attempts on successful login
     * 
     * @since 1.0.0
     * @param string $user_login Username
     * @param \WP_User $user User object
     * @return void
     */
    public static function handle_login_success($user_login, $user) {
        $ip = oyic_secure_login_get_client_ip();
        delete_transient('login_attempts_' . $ip);
        
        // Log successful login if logging is available
        if (function_exists('oyic_secure_login_log_event')) {
            oyic_secure_login_log_event('login_success', 'Successful login', array(
                'user_id' => $user->ID,
                'username' => $user_login,
                'ip' => $ip,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ));
        }
    }

    /**
     * Get current rate limit status for an IP
     * 
     * @since 1.0.0
     * @param string $ip IP address (optional, uses current IP if not provided)
     * @return array Rate limit status
     */
    public static function get_rate_limit_status($ip = null) {
        if ($ip === null) {
            $ip = oyic_secure_login_get_client_ip();
        }
        
        $key = 'login_attempts_' . $ip;
        $attempts = (int) get_transient($key);
        $timeout = get_option('_transient_timeout_' . $key, 0);
        
        return array(
            'ip' => $ip,
            'attempts' => $attempts,
            'remaining' => max(0, 5 - $attempts),
            'blocked_until' => $timeout,
            'is_blocked' => $attempts >= 5,
        );
    }

    /**
     * Clear rate limit for an IP
     * 
     * @since 1.0.0
     * @param string $ip IP address (optional, uses current IP if not provided)
     * @return bool True if cleared successfully
     */
    public static function clear_rate_limit($ip = null) {
        if ($ip === null) {
            $ip = oyic_secure_login_get_client_ip();
        }
        
        $key = 'login_attempts_' . $ip;
        return delete_transient($key);
    }
}

// Initialize security enhancements
OYIC_Security_Enhancements::init();

/**
 * Helper function to get rate limit status
 * 
 * @since 1.0.0
 * @param string $ip IP address (optional)
 * @return array Rate limit status
 */
function oyic_secure_login_get_rate_limit_status($ip = null) {
    return OYIC_Security_Enhancements::get_rate_limit_status($ip);
}

/**
 * Helper function to clear rate limit
 * 
 * @since 1.0.0
 * @param string $ip IP address (optional)
 * @return bool True if cleared successfully
 */
function oyic_secure_login_clear_rate_limit($ip = null) {
    return OYIC_Security_Enhancements::clear_rate_limit($ip);
}
