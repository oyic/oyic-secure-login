<?php
/**
 * Plugin Name: OYIC Secure Login
 * Plugin URI: https://github.com/oyic/oyic-secure-login
 * Description: Enhanced WordPress security with custom login URLs and email OTP authentication. Protect your site from brute force attacks and unauthorized access.
 * Version: 1.0.0
 * Requires at least: 5.0
 * Requires PHP: 7.4
 * Author: OYIC Team
 * Author URI: https://oyic.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: oyic-secure-login
 * Domain Path: /languages
 * Network: false
 * 
 * @package OYIC\SecureLogin
 * @since 1.0.0
 */

// Prevent direct access to this file
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

// Define plugin constants
define('OYIC_SECURE_LOGIN_VERSION', '1.0.0');
define('OYIC_SECURE_LOGIN_PLUGIN_FILE', __FILE__);
define('OYIC_SECURE_LOGIN_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('OYIC_SECURE_LOGIN_PLUGIN_URL', plugin_dir_url(__FILE__));
define('OYIC_SECURE_LOGIN_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Minimum PHP version check
if (version_compare(PHP_VERSION, '7.4', '<')) {
    if (!isset($_GET['activate']) && !isset($_GET['deactivate'])) {
        add_action('admin_notices', function() {
            echo '<div class="notice notice-error"><p>';
            printf(
                /* translators: 1: Current PHP version, 2: Required PHP version */
                esc_html__('OYIC Secure Login requires PHP %2$s or higher. You are running PHP %1$s.', 'oyic-secure-login'),
                PHP_VERSION,
                '7.4'
            );
            echo '</p></div>';
        });
    }
    return;
}

// WordPress version check
global $wp_version;
if (version_compare($wp_version, '5.0', '<')) {
    if (!isset($_GET['activate']) && !isset($_GET['deactivate'])) {
        add_action('admin_notices', function() {
            echo '<div class="notice notice-error"><p>';
            printf(
                /* translators: 1: Current WordPress version, 2: Required WordPress version */
                esc_html__('OYIC Secure Login requires WordPress %2$s or higher. You are running WordPress %1$s.', 'oyic-secure-login'),
                $GLOBALS['wp_version'],
                '5.0'
            );
            echo '</p></div>';
        });
    }
    return;
}

// Autoloader
require_once OYIC_SECURE_LOGIN_PLUGIN_DIR . 'includes/autoloader.php';

/**
 * Main plugin class
 * 
 * This class initializes the plugin and coordinates all functionality.
 * It follows the singleton pattern to ensure only one instance exists.
 * 
 * @since 1.0.0
 */
final class OYIC_Secure_Login {

    /**
     * Plugin instance
     * 
     * @since 1.0.0
     * @var OYIC_Secure_Login|null
     */
    private static $instance = null;

    /**
     * Plugin options
     * 
     * @since 1.0.0
     * @var array
     */
    private $options = array();

    /**
     * Plugin components
     * 
     * @since 1.0.0
     * @var array
     */
    private $components = array();

    /**
     * Get plugin instance
     * 
     * Implements the singleton pattern to ensure only one instance
     * of the plugin exists throughout the request lifecycle.
     * 
     * @since 1.0.0
     * @return OYIC_Secure_Login
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     * 
     * Private constructor to prevent direct instantiation.
     * Use get_instance() instead.
     * 
     * @since 1.0.0
     */
    private function __construct() {
        $this->init();
    }

    /**
     * Initialize the plugin
     * 
     * Sets up all hooks, loads components, and prepares the plugin
     * for operation. This method is called during plugin instantiation.
     * 
     * @since 1.0.0
     * @return void
     */
    private function init() {
        // Load plugin text domain for internationalization
        add_action('plugins_loaded', array($this, 'load_textdomain'));
        
        // Initialize plugin on WordPress init
        add_action('init', array($this, 'init_plugin'));
        
        // Handle plugin activation and deactivation
        register_activation_hook(OYIC_SECURE_LOGIN_PLUGIN_FILE, array($this, 'activate'));
        register_deactivation_hook(OYIC_SECURE_LOGIN_PLUGIN_FILE, array($this, 'deactivate'));
        
        // Admin initialization
        if (is_admin()) {
            // Debug: Log admin hook registration
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('OYIC Secure Login: Registering admin_init hook');
            }
            add_action('admin_init', array($this, 'init_admin'));
            add_action('admin_init', array($this, 'register_direct_settings'));
            
            // DIRECT ADMIN MENU REGISTRATION (bypass Admin Manager for now)
            add_action('admin_menu', array($this, 'add_direct_admin_menu'));
            
            // Handle settings updates
            add_action('update_option_oyic_secure_login_options', array($this, 'handle_settings_update'), 10, 2);
            
            // Handle AJAX requests
            add_action('wp_ajax_oyic_generate_key', array($this, 'generate_override_key_ajax'));
        }
        
        // Load plugin options
        $this->load_options();
        
        // Initialize security blocking
        $this->init_security_blocking();
        
        // Initialize custom URL routing
        $this->init_custom_url_routing();
    }

    /**
     * Load plugin text domain
     * 
     * Loads the plugin's translation files for internationalization support.
     * Supports both plugin directory and WordPress languages directory.
     * 
     * @since 1.0.0
     * @return void
     */
    public function load_textdomain() {
        $domain = 'oyic-secure-login';
        $locale = apply_filters('plugin_locale', get_locale(), $domain);
        
        // Load from WordPress languages directory first
        load_textdomain(
            $domain,
            WP_LANG_DIR . '/plugins/' . $domain . '-' . $locale . '.mo'
        );
        
        // Load from plugin languages directory as fallback
        load_plugin_textdomain(
            $domain,
            false,
            dirname(OYIC_SECURE_LOGIN_PLUGIN_BASENAME) . '/languages'
        );
    }

    /**
     * Initialize plugin components
     * 
     * Creates and initializes all plugin components including
     * authentication, admin interface, security features, etc.
     * 
     * @since 1.0.0
     * @return void
     */
    public function init_plugin() {
        // Prevent output during activation
        if (isset($_GET['activate']) || isset($_GET['deactivate'])) {
            ob_start();
        }
        
        try {
            // Initialize database tables
            $this->components['database'] = new \OYIC\SecureLogin\Database\Manager();
            
            // Initialize security features
            $this->components['security'] = new \OYIC\SecureLogin\Security\Manager();
            
            // Initialize authentication system
            $this->components['auth'] = new \OYIC\SecureLogin\Auth\Manager($this->options);
            
            // Initialize frontend features
            if (!is_admin()) {
                $this->components['frontend'] = new \OYIC\SecureLogin\Frontend\Manager($this->options);
            }
            
            /**
             * Fires after plugin initialization is complete
             * 
             * @since 1.0.0
             * @param OYIC_Secure_Login $plugin Plugin instance
             */
            do_action('oyic_secure_login_initialized', $this);
            
        } catch (Exception $e) {
            // Log error and show admin notice (but not during activation)
            error_log('OYIC Secure Login initialization error: ' . $e->getMessage());
            
            if (is_admin() && !isset($_GET['activate']) && !isset($_GET['deactivate'])) {
                add_action('admin_notices', function() use ($e) {
                    echo '<div class="notice notice-error"><p>';
                    printf(
                        /* translators: %s: Error message */
                        esc_html__('OYIC Secure Login initialization failed: %s', 'oyic-secure-login'),
                        esc_html($e->getMessage())
                    );
                    echo '</p></div>';
                });
            }
        }
        
        // Clean any output that might have been generated during activation
        if (isset($_GET['activate']) || isset($_GET['deactivate'])) {
            ob_end_clean();
        }
    }

    /**
     * Initialize admin components
     * 
     * Sets up admin-specific functionality including settings pages,
     * admin notices, and dashboard widgets.
     * 
     * @since 1.0.0
     * @return void
     */
    public function init_admin() {
        // Prevent multiple initializations
        if (isset($this->components['admin'])) {
            return;
        }
        
        // Debug: Log admin initialization
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Secure Login: Initializing admin manager');
        }
        
        try {
            $this->components['admin'] = new \OYIC\SecureLogin\Admin\Manager($this->options);
            
            // Debug: Log admin manager created
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('OYIC Secure Login: Admin manager created successfully');
            }
        } catch (Exception $e) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('OYIC Secure Login: Failed to create admin manager - ' . $e->getMessage());
            }
        } catch (Error $e) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('OYIC Secure Login: Fatal error creating admin manager - ' . $e->getMessage());
            }
        }
    }

    /**
     * Load plugin options
     * 
     * Retrieves plugin settings from the database and sets up
     * default values for any missing options.
     * 
     * @since 1.0.0
     * @return void
     */
    private function load_options() {
        $defaults = array(
            'enable_custom_login' => false,
            'custom_login_slug' => 'secure-access',
            'enable_otp_login' => false,
            'override_key' => '',
            'otp_expiry_minutes' => 10,
            'rate_limit_attempts' => 3,
            'rate_limit_window' => 5,
            'email_from_name' => get_bloginfo('name'),
            'email_from_address' => get_option('admin_email'),
        );

        $this->options = wp_parse_args(
            get_option('oyic_secure_login_options', array()),
            $defaults
        );

        // Generate override key if not set
        if (empty($this->options['override_key'])) {
            $this->options['override_key'] = wp_generate_password(16, false);
            $this->save_options();
        }
    }

    /**
     * Save plugin options
     * 
     * Saves the current plugin options to the database.
     * Includes validation and sanitization.
     * 
     * @since 1.0.0
     * @return bool True on success, false on failure
     */
    public function save_options() {
        return update_option('oyic_secure_login_options', $this->options);
    }

    /**
     * Get plugin options
     * 
     * Returns the current plugin options array.
     * 
     * @since 1.0.0
     * @param string $key Optional. Specific option key to retrieve
     * @return mixed All options array or specific option value
     */
    public function get_options($key = null) {
        if ($key !== null) {
            return isset($this->options[$key]) ? $this->options[$key] : null;
        }
        return $this->options;
    }

    /**
     * Update plugin option
     * 
     * Updates a specific plugin option and saves to database.
     * 
     * @since 1.0.0
     * @param string $key Option key
     * @param mixed $value Option value
     * @return bool True on success, false on failure
     */
    public function update_option($key, $value) {
        $this->options[$key] = $value;
        return $this->save_options();
    }

    /**
     * Get component instance
     * 
     * Returns a specific plugin component instance.
     * 
     * @since 1.0.0
     * @param string $component Component name
     * @return object|null Component instance or null if not found
     */
    public function get_component($component) {
        return isset($this->components[$component]) ? $this->components[$component] : null;
    }

    /**
     * Plugin activation handler
     * 
     * Runs when the plugin is activated. Sets up database tables,
     * default options, and flushes rewrite rules.
     * 
     * @since 1.0.0
     * @return void
     */
    public function activate() {
        // Start output buffering to catch any unexpected output
        ob_start();
        
        try {
            // Create database tables
            $database = new \OYIC\SecureLogin\Database\Manager();
            $database->create_tables();
            
            // Set default options
            $this->load_options();
            $this->save_options();
            
            // Schedule rewrite rules flush
            set_transient('oyic_secure_login_flush_rules', true, 60);
            
            // Clear any existing caches
            if (function_exists('wp_cache_flush')) {
                wp_cache_flush();
            }
            
            /**
             * Fires after plugin activation
             * 
             * @since 1.0.0
             */
            do_action('oyic_secure_login_activated');
            
        } catch (Exception $e) {
            // Log activation error
            error_log('OYIC Secure Login activation error: ' . $e->getMessage());
        }
        
        // Clean any output that might have been generated
        ob_end_clean();
    }

    /**
     * Plugin deactivation handler
     * 
     * Runs when the plugin is deactivated. Cleans up temporary data
     * and flushes rewrite rules.
     * 
     * @since 1.0.0
     * @return void
     */
    public function deactivate() {
        // Clean up transients
        delete_transient('oyic_secure_login_flush_rules');
        
        // Flush rewrite rules
        flush_rewrite_rules();
        
        // Clear caches
        wp_cache_flush();
        
        /**
         * Fires after plugin deactivation
         * 
         * @since 1.0.0
         */
        do_action('oyic_secure_login_deactivated');
    }

    /**
     * Initialize custom URL routing
     * 
     * @since 1.0.0
     * @return void
     */
    public function init_custom_url_routing() {
        // Add rewrite rules for custom login URL
        add_action('init', array($this, 'add_custom_login_rewrite_rules'));
        
        // Register query variable
        add_filter('query_vars', array($this, 'add_query_vars'));
        
        // Handle custom login URL requests
        add_action('template_redirect', array($this, 'handle_custom_login_request'));
    }

    /**
     * Initialize security blocking
     * 
     * @since 1.0.0
     * @return void
     */
    public function init_security_blocking() {
        // Block wp-login.php access
        add_action('login_init', array($this, 'block_wp_login'));
        
        // Block wp-admin access for non-logged-in users
        add_action('admin_init', array($this, 'block_wp_admin'));
        
        // Handle logout redirects
        add_action('wp_logout', array($this, 'handle_logout_redirect'));
        
        // Fix logout URL
        add_filter('logout_url', array($this, 'fix_logout_url'), 10, 2);
        
        // Fix admin bar logout link
        add_action('wp_before_admin_bar_render', array($this, 'fix_admin_bar_logout'));
        
        // Add OTP verification hooks
        add_action('wp_authenticate', array($this, 'handle_otp_authentication'), 30, 2);
    }

    /**
     * Block wp-login.php access
     * 
     * @since 1.0.0
     * @return void
     */
    public function block_wp_login() {
        $options = $this->get_options();
        
        // Only block if login blocking is enabled
        if (!isset($options['enable_custom_login']) || !$options['enable_custom_login']) {
            return;
        }
        
        // Allow logout actions
        if (isset($_GET['action']) && $_GET['action'] === 'logout') {
            return;
        }
        
        // Allow logged-in users (for logout redirect)
        if (is_user_logged_in()) {
            return;
        }
        
        // Allow emergency override
        if (isset($_GET['override']) && !empty($_GET['override'])) {
            $override_key = isset($options['override_key']) ? $options['override_key'] : '';
            if (!empty($override_key) && hash_equals($override_key, $_GET['override'])) {
                // Auto-login the first admin user if no specific user provided
                if (isset($_GET['auto_user']) && !empty($_GET['auto_user'])) {
                    $this->handle_emergency_auto_login($_GET['auto_user'], $_GET['override']);
                    return;
                } else {
                    // Auto-login first admin user
                    $admin_users = get_users(array('role' => 'administrator', 'number' => 1));
                    if (!empty($admin_users)) {
                        $this->handle_emergency_auto_login($admin_users[0]->ID, $_GET['override']);
                        return;
                    }
                }
                
                // Fallback: Valid override key, allow normal login but show emergency notice
                add_action('login_message', function() {
                    return '<div class="message" style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin-bottom: 20px; border-radius: 4px;">
                        <strong>Emergency Access:</strong> You are using the emergency override key. Please login normally.
                    </div>';
                });
                return;
            }
        }
        
        // Allow AJAX requests
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }
        
        // Allow cron
        if (defined('DOING_CRON') && DOING_CRON) {
            return;
        }
        
        // Block access - show 403 error (no OTP form here)
        status_header(403);
        nocache_headers();
        
        echo '<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; text-align: center; }
        .error { color: #d63384; }
        .container { max-width: 500px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="error">Access Denied</h1>
        <p>Direct access to the login page has been disabled for security reasons.</p>
        <p>If you are a legitimate user, please contact the site administrator.</p>
    </div>
</body>
</html>';
        
        exit;
    }

    /**
     * Block wp-admin access for non-logged-in users
     * 
     * @since 1.0.0
     * @return void
     */
    public function block_wp_admin() {
        $options = $this->get_options();
        
        // Only block if custom login is enabled
        if (!isset($options['enable_custom_login']) || !$options['enable_custom_login']) {
            return;
        }
        
        // Allow logged-in users
        if (is_user_logged_in()) {
            return;
        }
        
        // Allow AJAX requests
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }
        
        // Allow cron
        if (defined('DOING_CRON') && DOING_CRON) {
            return;
        }
        
        // Block access - show 403 error
        status_header(403);
        nocache_headers();
        
        echo '<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; text-align: center; }
        .error { color: #d63384; }
        .container { max-width: 500px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="error">Access Denied</h1>
        <p>Direct access to the admin area has been disabled for security reasons.</p>
        <p>If you are a legitimate user, please contact the site administrator.</p>
    </div>
</body>
</html>';
        
        exit;
    }

    /**
     * Add query vars
     * 
     * @since 1.0.0
     * @param array $vars Query variables
     * @return array Modified query variables
     */
    public function add_query_vars($vars) {
        $vars[] = 'oyic_secure_login';
        return $vars;
    }

    /**
     * Add custom login rewrite rules
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_custom_login_rewrite_rules() {
        $options = $this->get_options();
        
        // Only add rules if blocking is enabled
        if (!isset($options['enable_custom_login']) || !$options['enable_custom_login']) {
            return;
        }
        
        $custom_url = isset($options['custom_login_url']) ? $options['custom_login_url'] : 'secure-access';
        $custom_url = sanitize_title($custom_url);
        
        if (!empty($custom_url)) {
            add_rewrite_rule(
                '^' . $custom_url . '/?$',
                'index.php?oyic_secure_login=1',
                'top'
            );
        }
        
        // Check if we need to flush rewrite rules
        if (get_transient('oyic_flush_rewrite_rules')) {
            delete_transient('oyic_flush_rewrite_rules');
            flush_rewrite_rules();
            
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('OYIC Secure Login: Rewrite rules flushed');
            }
        }
    }

    /**
     * Handle emergency auto-login
     * 
     * @since 1.0.0
     * @param string $user_identifier User ID, username, or email
     * @param string $override_key Override key for verification
     * @return void
     */
    public function handle_emergency_auto_login($user_identifier, $override_key) {
        $options = $this->get_options();
        $stored_key = isset($options['override_key']) ? $options['override_key'] : '';
        
        // Verify override key
        if (empty($stored_key) || !hash_equals($stored_key, $override_key)) {
            wp_die('Invalid emergency access key.');
        }
        
        // Get user
        $user = false;
        if (is_numeric($user_identifier)) {
            $user = get_user_by('id', $user_identifier);
        } else if (is_email($user_identifier)) {
            $user = get_user_by('email', $user_identifier);
        } else {
            $user = get_user_by('login', $user_identifier);
        }
        
        if (!$user) {
            wp_die('User not found for emergency access.');
        }
        
        // Log the user in
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        
        // Redirect to admin
        wp_redirect(admin_url());
        exit;
    }

    /**
     * Handle custom login request
     * 
     * @since 1.0.0
     * @return void
     */
    public function handle_custom_login_request() {
        if (get_query_var('oyic_secure_login')) {
            // Check if user wants OTP mode
            $use_otp = isset($_GET['mode']) && $_GET['mode'] === 'otp';
            
            if ($use_otp) {
                $this->show_otp_login_form();
            } else {
                $this->show_custom_login_form();
            }
            exit;
        }
    }

    /**
     * Show custom login form
     * 
     * @since 1.0.0
     * @return void
     */
    public function show_custom_login_form() {
        $message = '';
        $error = '';
        
        // Check if user was redirected after logout
        if (isset($_GET['loggedout']) && $_GET['loggedout'] === 'true') {
            $message = 'You have been logged out successfully.';
        }
        
        // Handle login form submission
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'custom_login') {
            $username = sanitize_text_field($_POST['username']);
            $password = $_POST['password'];
            
            $user = wp_authenticate($username, $password);
            
            if (is_wp_error($user)) {
                $error = $user->get_error_message();
            } else {
                // Login successful
                wp_set_current_user($user->ID);
                wp_set_auth_cookie($user->ID, !empty($_POST['remember']));
                
                // Redirect to admin or requested page
                $redirect_to = isset($_GET['redirect_to']) ? $_GET['redirect_to'] : admin_url();
                wp_redirect($redirect_to);
                exit;
            }
        }
        
        $options = $this->get_options();
        $otp_enabled = isset($options['enable_otp_login']) && $options['enable_otp_login'];
        $current_url = home_url($_SERVER['REQUEST_URI']);
        $otp_url = add_query_arg('mode', 'otp', $current_url);
        
        echo '<!DOCTYPE html>
<html>
<head>
    <title>Secure Login - ' . esc_html(get_bloginfo('name')) . '</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            background: #f1f1f1; 
            margin: 0; 
            padding: 50px 20px; 
        }
        .container { 
            max-width: 400px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }
        h1 { 
            text-align: center; 
            margin-bottom: 30px; 
            color: #333; 
        }
        .form-group { 
            margin-bottom: 20px; 
        }
        label { 
            display: block; 
            margin-bottom: 8px; 
            font-weight: 500; 
        }
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 12px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            box-sizing: border-box; 
            font-size: 16px; 
        }
        .button { 
            width: 100%; 
            padding: 12px; 
            background: #0073aa; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            font-size: 16px; 
            cursor: pointer; 
            margin-bottom: 10px;
        }
        .button:hover { 
            background: #005a87; 
        }
        .button-secondary {
            background: #f7f7f7;
            color: #555;
            border: 1px solid #ccc;
        }
        .button-secondary:hover {
            background: #e9e9e9;
        }
        .message { 
            background: #d4edda; 
            border: 1px solid #c3e6cb; 
            color: #155724; 
            padding: 12px; 
            border-radius: 4px; 
            margin-bottom: 20px; 
        }
        .error { 
            background: #f8d7da; 
            border: 1px solid #f5c6cb; 
            color: #721c24; 
            padding: 12px; 
            border-radius: 4px; 
            margin-bottom: 20px; 
        }
        .remember-me {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }
        .remember-me input {
            width: auto;
            margin-right: 8px;
        }
        .alternative-methods {
            text-align: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        .alt-link {
            color: #0073aa;
            text-decoration: none;
            font-size: 14px;
        }
        .alt-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Secure Login</h1>';
        
        if (!empty($message)) {
            echo '<div class="message">' . esc_html($message) . '</div>';
        }
        
        if (!empty($error)) {
            echo '<div class="error">' . esc_html($error) . '</div>';
        }
        
        echo '<form method="post">
            <div class="form-group">
                <label for="username">Username or Email:</label>
                <input type="text" name="username" id="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" name="password" id="password" required>
            </div>
            <div class="remember-me">
                <input type="checkbox" name="remember" id="remember" value="1">
                <label for="remember">Remember Me</label>
            </div>
            <input type="hidden" name="action" value="custom_login">
            <button type="submit" class="button">Log In</button>
        </form>
        
        <div class="alternative-methods">';
        
        if ($otp_enabled) {
            echo '<p><a href="' . esc_url($otp_url) . '" class="alt-link">→ Login with Email OTP instead</a></p>';
        }
        
        echo '<p><a href="' . esc_url(home_url()) . '" class="alt-link">← Back to Website</a></p>
        </div>
    </div>
</body>
</html>';
    }

    /**
     * Handle logout redirect
     * 
     * @since 1.0.0
     * @return void
     */
    public function handle_logout_redirect() {
        // This method is called after logout
        // The logout URL fix will handle the redirect
    }

    /**
     * Fix logout URL
     * 
     * @since 1.0.0
     * @param string $logout_url Logout URL
     * @param string $redirect Redirect URL
     * @return string Modified logout URL
     */
    public function fix_logout_url($logout_url, $redirect) {
        $options = $this->get_options();
        
        // Only modify if blocking is enabled
        if (!isset($options['enable_custom_login']) || !$options['enable_custom_login']) {
            return $logout_url;
        }
        
        // Redirect to custom URL or emergency override after logout
        $custom_url = isset($options['custom_login_url']) ? $options['custom_login_url'] : 'secure-access';
        $override_key = isset($options['override_key']) ? $options['override_key'] : '';
        
        if (!empty($custom_url)) {
            // Redirect to custom login URL with logout message
            $redirect_url = add_query_arg('loggedout', 'true', home_url('/' . $custom_url . '/'));
            $logout_url = add_query_arg('redirect_to', $redirect_url, $logout_url);
        } else if (!empty($override_key)) {
            // Fallback to emergency override
            $redirect_url = add_query_arg('loggedout', 'true', wp_login_url() . '?override=' . $override_key);
            $logout_url = add_query_arg('redirect_to', $redirect_url, $logout_url);
        } else {
            // If no custom URL or override key, redirect to home page
            $logout_url = add_query_arg('redirect_to', home_url(), $logout_url);
        }
        
        return $logout_url;
    }

    /**
     * Fix admin bar logout link
     * 
     * @since 1.0.0
     * @return void
     */
    public function fix_admin_bar_logout() {
        global $wp_admin_bar;
        
        $options = $this->get_options();
        
        // Only modify if blocking is enabled
        if (!isset($options['enable_custom_login']) || !$options['enable_custom_login']) {
            return;
        }
        
        $custom_url = isset($options['custom_login_url']) ? $options['custom_login_url'] : 'secure-access';
        $override_key = isset($options['override_key']) ? $options['override_key'] : '';
        
        // Get the logout node
        $logout_node = $wp_admin_bar->get_node('logout');
        if ($logout_node) {
            // Update the logout URL to redirect to custom URL or emergency override
            if (!empty($custom_url)) {
                $redirect_url = add_query_arg('loggedout', 'true', home_url('/' . $custom_url . '/'));
            } else if (!empty($override_key)) {
                $redirect_url = add_query_arg('loggedout', 'true', wp_login_url() . '?override=' . $override_key);
            } else {
                $redirect_url = home_url();
            }
            
            $logout_node->href = wp_logout_url($redirect_url);
            $wp_admin_bar->add_node($logout_node);
        }
    }

    /**
     * Show OTP login form
     * 
     * @since 1.0.0
     * @return void
     */
    public function show_otp_login_form() {
        // Handle OTP form submissions
        $message = '';
        $error = '';
        
        // Check if user was redirected after logout
        if (isset($_GET['loggedout']) && $_GET['loggedout'] === 'true') {
            $message = 'You have been logged out successfully.';
        }
        
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (isset($_POST['action']) && $_POST['action'] === 'request_otp') {
                // Request OTP
                $username = sanitize_text_field($_POST['username']);
                if ($this->send_otp_code($username)) {
                    $message = 'OTP code sent to your email address. Please check your email and enter the code below.';
                } else {
                    $error = 'Invalid username or email address.';
                }
            } elseif (isset($_POST['action']) && $_POST['action'] === 'verify_otp') {
                // Verify OTP
                $username = sanitize_text_field($_POST['username']);
                $otp_code = sanitize_text_field($_POST['otp_code']);
                if ($this->verify_otp_code($username, $otp_code)) {
                    // Success - user is logged in, redirect handled in verify_otp_code
                    return;
                } else {
                    $error = 'Invalid or expired OTP code. Please try again.';
                }
            }
        }
        
        $step = (isset($_POST['action']) && $_POST['action'] === 'request_otp' && empty($error)) ? 'verify' : 'request';
        $username = isset($_POST['username']) ? sanitize_text_field($_POST['username']) : '';
        
        echo '<!DOCTYPE html>
<html>
<head>
    <title>Secure Login - ' . esc_html(get_bloginfo('name')) . '</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            background: #f1f1f1; 
            margin: 0; 
            padding: 50px 20px; 
        }
        .container { 
            max-width: 400px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }
        h1 { 
            text-align: center; 
            margin-bottom: 30px; 
            color: #333; 
        }
        .form-group { 
            margin-bottom: 20px; 
        }
        label { 
            display: block; 
            margin-bottom: 8px; 
            font-weight: 500; 
        }
        input[type="text"], input[type="email"] { 
            width: 100%; 
            padding: 12px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            box-sizing: border-box; 
            font-size: 16px; 
        }
        .button { 
            width: 100%; 
            padding: 12px; 
            background: #0073aa; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            font-size: 16px; 
            cursor: pointer; 
        }
        .button:hover { 
            background: #005a87; 
        }
        .message { 
            background: #d4edda; 
            border: 1px solid #c3e6cb; 
            color: #155724; 
            padding: 12px; 
            border-radius: 4px; 
            margin-bottom: 20px; 
        }
        .error { 
            background: #f8d7da; 
            border: 1px solid #f5c6cb; 
            color: #721c24; 
            padding: 12px; 
            border-radius: 4px; 
            margin-bottom: 20px; 
        }
        .back-link { 
            text-align: center; 
            margin-top: 20px; 
        }
        .back-link a { 
            color: #0073aa; 
            text-decoration: none; 
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Secure Login</h1>';
        
        if (!empty($message)) {
            echo '<div class="message">' . esc_html($message) . '</div>';
        }
        
        if (!empty($error)) {
            echo '<div class="error">' . esc_html($error) . '</div>';
        }
        
        if ($step === 'request') {
            echo '<form method="post">
                <div class="form-group">
                    <label for="username">Username or Email:</label>
                    <input type="text" name="username" id="username" value="' . esc_attr($username) . '" required>
                </div>
                <input type="hidden" name="action" value="request_otp">
                <button type="submit" class="button">Send OTP Code</button>
            </form>';
        } else {
            echo '<form method="post">
                <div class="form-group">
                    <label for="otp_code">Enter OTP Code:</label>
                    <input type="text" name="otp_code" id="otp_code" maxlength="6" required>
                </div>
                <input type="hidden" name="username" value="' . esc_attr($username) . '">
                <input type="hidden" name="action" value="verify_otp">
                <button type="submit" class="button">Verify Code</button>
            </form>
            <div class="back-link">
                <a href="' . remove_query_arg('mode') . '">← Back to Regular Login</a> | 
                <a href="' . $_SERVER['REQUEST_URI'] . '">← Request new code</a>
            </div>';
        }
        
        echo '</div>
</body>
</html>';
    }

    /**
     * Handle OTP authentication
     * 
     * @since 1.0.0
     * @param string $username Username
     * @param string $password Password
     * @return void
     */
    public function handle_otp_authentication($username, $password) {
        // This method is now handled by show_otp_login_form
        return;
    }

    /**
     * Send OTP code to user
     * 
     * @since 1.0.0
     * @param string $username Username or email
     * @return bool Success status
     */
    private function send_otp_code($username) {
        // Get user by username or email
        $user = get_user_by('login', $username);
        if (!$user) {
            $user = get_user_by('email', $username);
        }
        
        if (!$user) {
            return false; // Invalid user
        }
        
        // Generate OTP code (6 digits only)
        $otp_code = sprintf('%06d', mt_rand(0, 999999));
        
        // Store OTP in database
        $this->store_otp($user->user_email, $otp_code);
        
        // Send OTP email
        $options = $this->get_options();
        $from_name = isset($options['email_from_name']) ? $options['email_from_name'] : get_bloginfo('name');
        $from_email = isset($options['email_from_address']) ? $options['email_from_address'] : get_option('admin_email');
        
        $subject = sprintf(__('Login Verification Code for %s', 'oyic-secure-login'), get_bloginfo('name'));
        $message = sprintf(
            __("Hello %s,\n\nYour login verification code is: %s\n\nThis code will expire in %d minutes.\n\nIf you didn't request this code, please ignore this email.\n\nBest regards,\n%s"),
            $user->display_name,
            $otp_code,
            isset($options['otp_expiry_minutes']) ? $options['otp_expiry_minutes'] : 15,
            $from_name
        );
        
        // Set email headers
        $headers = array(
            'From: ' . $from_name . ' <' . $from_email . '>',
            'Content-Type: text/plain; charset=UTF-8'
        );
        
        $sent = wp_mail($user->user_email, $subject, $message, $headers);
        
        return $sent;
    }

    /**
     * Store OTP code (simplified version)
     * 
     * @since 1.0.0
     * @param string $email User email
     * @param string $otp_code OTP code
     * @return void
     */
    private function store_otp($email, $otp_code) {
        // For now, store in transients (temporary solution)
        $options = $this->get_options();
        $expiry = (isset($options['otp_expiry_minutes']) ? $options['otp_expiry_minutes'] : 15) * 60; // Convert to seconds
        set_transient('oyic_otp_' . md5($email), $otp_code, $expiry);
    }

    /**
     * Verify OTP code
     * 
     * @since 1.0.0
     * @param string $username Username
     * @param string $otp_code OTP code
     * @return bool Success status
     */
    private function verify_otp_code($username, $otp_code) {
        $user = get_user_by('login', $username);
        if (!$user) {
            $user = get_user_by('email', $username);
        }
        
        if (!$user) {
            return false;
        }
        
        // Get stored OTP
        $stored_otp = get_transient('oyic_otp_' . md5($user->user_email));
        
        if ($stored_otp && hash_equals($stored_otp, trim($otp_code))) {
            // Valid OTP - log the user in
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);
            
            // Clean up OTP
            delete_transient('oyic_otp_' . md5($user->user_email));
            
            // Redirect to admin
            wp_redirect(admin_url());
            exit;
        }
        
        return false;
    }

    /**
     * Generate override key via AJAX
     * 
     * @since 1.0.0
     * @return void
     */
    public function generate_override_key_ajax() {
        // Check permissions and nonce
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'oyic-secure-login'));
        }
        
        if (!wp_verify_nonce($_POST['nonce'], 'oyic_secure_login_admin')) {
            wp_send_json_error(__('Invalid nonce.', 'oyic-secure-login'));
        }
        
        // Generate new key
        $new_key = wp_generate_password(32, false);
        
        // Update options
        $options = get_option('oyic_secure_login_options', array());
        $options['override_key'] = $new_key;
        update_option('oyic_secure_login_options', $options);
        
        // Return new key and emergency URL
        $emergency_url = wp_login_url() . '?override=' . $new_key;
        
        wp_send_json_success(array(
            'key' => $new_key,
            'emergency_url' => $emergency_url
        ));
    }

    /**
     * Handle settings update
     * 
     * @since 1.0.0
     * @param array $old_value Old option value
     * @param array $new_value New option value
     * @return void
     */
    public function handle_settings_update($old_value, $new_value) {
        // Debug: Log settings update
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Secure Login: Settings updated');
        }
        
        // Update plugin options
        $this->options = $new_value;
        
        // Check if blocking was enabled/disabled
        $old_enabled = isset($old_value['enable_custom_login']) ? $old_value['enable_custom_login'] : 0;
        $new_enabled = isset($new_value['enable_custom_login']) ? $new_value['enable_custom_login'] : 0;
        
        // Check if custom URL changed
        $old_url = isset($old_value['custom_login_url']) ? $old_value['custom_login_url'] : 'secure-access';
        $new_url = isset($new_value['custom_login_url']) ? $new_value['custom_login_url'] : 'secure-access';
        
        if ($old_enabled !== $new_enabled || $old_url !== $new_url) {
            // Set flag to flush rewrite rules on next init
            set_transient('oyic_flush_rewrite_rules', 1, 60);
            
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('OYIC Secure Login: Scheduled rewrite rules flush - Blocking: ' . ($new_enabled ? 'enabled' : 'disabled') . ', URL: ' . $new_url);
            }
        }
    }

    /**
     * Register direct settings (bypass Admin Manager)
     * 
     * @since 1.0.0
     * @return void
     */
    public function register_direct_settings() {
        // Debug: Log settings registration
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Secure Login: Registering direct settings');
        }
        
        register_setting(
            'oyic_secure_login_settings',
            'oyic_secure_login_options'
        );

        // Main settings section
        add_settings_section(
            'oyic_secure_login_main',
            __('Security Settings', 'oyic-secure-login'),
            function() {
                echo '<p>' . esc_html__('Configure your custom login URL and security settings.', 'oyic-secure-login') . '</p>';
            },
            'oyic-secure-login'
        );

        // Enable login blocking
        add_settings_field(
            'enable_custom_login',
            __('Enable Login Blocking', 'oyic-secure-login'),
            function() {
                $options = get_option('oyic_secure_login_options', array());
                $enabled = isset($options['enable_custom_login']) ? $options['enable_custom_login'] : 0;
                echo '<input type="checkbox" name="oyic_secure_login_options[enable_custom_login]" value="1" ' . checked(1, $enabled, false) . ' />';
                echo '<p class="description">' . esc_html__('Block direct access to wp-login.php and wp-admin for security.', 'oyic-secure-login') . '</p>';
                echo '<p class="description" style="color: #d63384;"><strong>' . esc_html__('Warning: Make sure to configure emergency access and/or custom URL before enabling!', 'oyic-secure-login') . '</strong></p>';
            },
            'oyic-secure-login',
            'oyic_secure_login_main'
        );

        // Custom Login URL
        add_settings_field(
            'custom_login_url',
            __('Custom Login URL', 'oyic-secure-login'),
            function() {
                $options = get_option('oyic_secure_login_options', array());
                $custom_url = isset($options['custom_login_url']) ? $options['custom_login_url'] : 'secure-access';
                echo '<input type="text" name="oyic_secure_login_options[custom_login_url]" value="' . esc_attr($custom_url) . '" class="regular-text" />';
                echo '<p class="description">' . sprintf(
                    esc_html__('Custom URL slug for secure login. Access via: %s', 'oyic-secure-login'),
                    '<code>' . esc_html(home_url('/' . $custom_url . '/')) . '</code>'
                ) . '</p>';
                echo '<p class="description">' . esc_html__('Only this URL will show the secure login form. All other access will be denied.', 'oyic-secure-login') . '</p>';
            },
            'oyic-secure-login',
            'oyic_secure_login_main'
        );

        // Emergency override key
        add_settings_field(
            'override_key',
            __('Emergency Override Key', 'oyic-secure-login'),
            function() {
                $options = get_option('oyic_secure_login_options', array());
                $key = isset($options['override_key']) ? $options['override_key'] : '';
                if (empty($key)) {
                    $key = wp_generate_password(32, false);
                }
                $emergency_url = wp_login_url() . '?override=' . $key;
                
                echo '<div class="override-key-section">';
                echo '<input type="text" id="override_key_field" name="oyic_secure_login_options[override_key]" value="' . esc_attr($key) . '" class="regular-text" readonly />';
                echo '<button type="button" class="button" onclick="generateOverrideKey()" style="margin-left: 10px;">Generate New Key</button>';
                echo '<button type="button" class="button" onclick="copyOverrideKey()" style="margin-left: 5px;">Copy Key</button>';
                echo '</div>';
                
                echo '<div class="emergency-url-section" style="margin-top: 15px;">';
                echo '<label><strong>' . esc_html__('Emergency Access URL:', 'oyic-secure-login') . '</strong></label><br>';
                echo '<input type="text" id="emergency_url_field" value="' . esc_attr($emergency_url) . '" class="widefat" readonly style="margin-top: 5px;" />';
                echo '<button type="button" class="button" onclick="copyEmergencyURL()" style="margin-top: 5px;">Copy URL</button>';
                echo '</div>';
                
                echo '<p class="description" style="margin-top: 15px; color: #d63384;"><strong>' . esc_html__('Keep this key and URL safe! You\'ll need them for emergency access when login is blocked.', 'oyic-secure-login') . '</strong></p>';
            },
            'oyic-secure-login',
            'oyic_secure_login_main'
        );

        // OTP Authentication Settings Section
        add_settings_section(
            'oyic_secure_login_otp',
            __('Email OTP Settings', 'oyic-secure-login'),
            function() {
                echo '<p>' . esc_html__('Configure email-based one-time password authentication as an alternative access method.', 'oyic-secure-login') . '</p>';
            },
            'oyic-secure-login'
        );

        // Enable OTP Login
        add_settings_field(
            'enable_otp_login',
            __('Enable Email OTP Access', 'oyic-secure-login'),
            function() {
                $options = get_option('oyic_secure_login_options', array());
                $enabled = isset($options['enable_otp_login']) ? $options['enable_otp_login'] : 0;
                echo '<input type="checkbox" name="oyic_secure_login_options[enable_otp_login]" value="1" ' . checked(1, $enabled, false) . ' />';
                echo '<p class="description">' . esc_html__('Allow legitimate users to request email OTP codes for access when login is blocked.', 'oyic-secure-login') . '</p>';
            },
            'oyic-secure-login',
            'oyic_secure_login_otp'
        );

        // OTP Expiry Time
        add_settings_field(
            'otp_expiry_minutes',
            __('OTP Code Expiry', 'oyic-secure-login'),
            function() {
                $options = get_option('oyic_secure_login_options', array());
                $expiry = isset($options['otp_expiry_minutes']) ? $options['otp_expiry_minutes'] : 15;
                echo '<input type="number" name="oyic_secure_login_options[otp_expiry_minutes]" value="' . esc_attr($expiry) . '" min="1" max="60" class="small-text" />';
                echo ' ' . esc_html__('minutes', 'oyic-secure-login');
                echo '<p class="description">' . esc_html__('How long OTP codes remain valid (1-60 minutes).', 'oyic-secure-login') . '</p>';
            },
            'oyic-secure-login',
            'oyic_secure_login_otp'
        );

        // Email From Name
        add_settings_field(
            'email_from_name',
            __('Email From Name', 'oyic-secure-login'),
            function() {
                $options = get_option('oyic_secure_login_options', array());
                $name = isset($options['email_from_name']) ? $options['email_from_name'] : get_bloginfo('name');
                echo '<input type="text" name="oyic_secure_login_options[email_from_name]" value="' . esc_attr($name) . '" class="regular-text" />';
                echo '<p class="description">' . esc_html__('Name that appears in OTP emails.', 'oyic-secure-login') . '</p>';
            },
            'oyic-secure-login',
            'oyic_secure_login_otp'
        );

        // Email From Address
        add_settings_field(
            'email_from_address',
            __('Email From Address', 'oyic-secure-login'),
            function() {
                $options = get_option('oyic_secure_login_options', array());
                $email = isset($options['email_from_address']) ? $options['email_from_address'] : get_option('admin_email');
                echo '<input type="email" name="oyic_secure_login_options[email_from_address]" value="' . esc_attr($email) . '" class="regular-text" />';
                echo '<button type="button" class="button" onclick="testEmail()" style="margin-left: 10px;">' . esc_html__('Test Email', 'oyic-secure-login') . '</button>';
                echo '<p class="description">' . esc_html__('Email address that sends OTP codes.', 'oyic-secure-login') . '</p>';
            },
            'oyic-secure-login',
            'oyic_secure_login_otp'
        );
    }

    /**
     * Add direct admin menu (bypass Admin Manager)
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_direct_admin_menu() {
        // Debug: Log direct menu registration
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Secure Login: Adding direct admin menu');
        }
        
        $hook = add_options_page(
            __('OYIC Secure Login Settings', 'oyic-secure-login'),
            __('Secure Login', 'oyic-secure-login'),
            'manage_options',
            'oyic-secure-login',
            array($this, 'direct_admin_page')
        );
        
        // Debug: Log menu hook result
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Secure Login: Direct menu hook result: ' . ($hook ? $hook : 'FAILED'));
        }
    }

    /**
     * Direct admin page callback (bypass Admin Manager)
     * 
     * @since 1.0.0
     * @return void
     */
    public function direct_admin_page() {
        // Debug: Log admin page access
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Secure Login: direct_admin_page() called');
            error_log('OYIC Secure Login: User can manage_options: ' . (current_user_can('manage_options') ? 'YES' : 'NO'));
        }
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'oyic-secure-login'));
        }

        // Try the direct template first, fallback to original
        $direct_template = OYIC_SECURE_LOGIN_PLUGIN_DIR . 'templates/direct-admin-page.php';
        $original_template = OYIC_SECURE_LOGIN_PLUGIN_DIR . 'templates/admin-page.php';
        
        // Debug: Log template info
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Secure Login: Direct template exists: ' . (file_exists($direct_template) ? 'YES' : 'NO'));
            error_log('OYIC Secure Login: Original template exists: ' . (file_exists($original_template) ? 'YES' : 'NO'));
        }
        
        if (file_exists($direct_template)) {
            include $direct_template;
        } else if (file_exists($original_template)) {
            include $original_template;
        } else {
            echo '<div class="wrap"><h1>OYIC Secure Login Settings</h1>';
            echo '<div class="error"><p>No template files found!</p></div>';
            echo '<p>Plugin directory: ' . esc_html(OYIC_SECURE_LOGIN_PLUGIN_DIR) . '</p>';
            echo '<p>Looking for: templates/direct-admin-page.php or templates/admin-page.php</p>';
            echo '</div>';
        }
    }

    /**
     * Prevent cloning
     * 
     * @since 1.0.0
     * @return void
     */
    private function __clone() {}

    /**
     * Prevent unserialization
     * 
     * @since 1.0.0
     * @return void
     */
    public function __wakeup() {}
}

/**
 * Get the main plugin instance
 * 
 * Convenience function to get the plugin instance from anywhere.
 * 
 * @since 1.0.0
 * @return OYIC_Secure_Login Plugin instance
 */
function oyic_secure_login() {
    return OYIC_Secure_Login::get_instance();
}

// Initialize the plugin
oyic_secure_login();

// Debug: Log plugin initialization
if (defined('WP_DEBUG') && WP_DEBUG) {
    error_log('OYIC Secure Login: Plugin initialized successfully');
}


