<?php
/**
 * Frontend Manager Class
 * 
 * Handles frontend functionality including custom login page display,
 * URL rewriting, and public-facing features.
 * 
 * @package OYIC\SecureLogin\Frontend
 * @since 1.0.0
 */

namespace OYIC\SecureLogin\Frontend;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Frontend Manager
 * 
 * Manages all frontend functionality for the plugin.
 * 
 * @since 1.0.0
 */
class Manager {

    /**
     * Plugin options
     * 
     * @since 1.0.0
     * @var array
     */
    private $options;

    /**
     * Constructor
     * 
     * @since 1.0.0
     * @param array $options Plugin options
     */
    public function __construct($options = array()) {
        $this->options = $options;
        $this->init();
    }

    /**
     * Initialize frontend functionality
     * 
     * @since 1.0.0
     * @return void
     */
    private function init() {
        // Add rewrite rules
        add_action('init', array($this, 'add_rewrite_rules'));
        
        // Handle custom login page
        add_action('template_redirect', array($this, 'handle_custom_login_page'));
        
        // Enqueue frontend scripts and styles
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        
        // Add query vars
        add_filter('query_vars', array($this, 'add_query_vars'));
        
        // Flush rewrite rules if needed
        add_action('wp_loaded', array($this, 'maybe_flush_rewrite_rules'));
        
        // Customize login URL in WordPress
        add_filter('login_url', array($this, 'custom_login_url'), 10, 3);
        
        // Customize logout URL
        add_filter('logout_url', array($this, 'custom_logout_url'), 10, 2);
        
        // Add body classes for custom login page
        add_filter('body_class', array($this, 'add_body_classes'));
        
        // Customize page title for login page
        add_filter('wp_title', array($this, 'custom_login_title'), 10, 2);
        add_filter('document_title_parts', array($this, 'custom_login_title_parts'));
    }

    /**
     * Add rewrite rules for custom login URL
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_rewrite_rules() {
        $slug = $this->options['custom_login_slug'] ?? 'secure-access';
        
        add_rewrite_rule(
            '^' . preg_quote($slug) . '/?$',
            'index.php?oyic_secure_login=1',
            'top'
        );
        
        add_rewrite_rule(
            '^' . preg_quote($slug) . '/([^/]+)/?$',
            'index.php?oyic_secure_login=1&login_action=$matches[1]',
            'top'
        );
    }

    /**
     * Add query variables
     * 
     * @since 1.0.0
     * @param array $vars Query variables
     * @return array Modified query variables
     */
    public function add_query_vars($vars) {
        $vars[] = 'oyic_secure_login';
        $vars[] = 'login_action';
        return $vars;
    }

    /**
     * Maybe flush rewrite rules
     * 
     * @since 1.0.0
     * @return void
     */
    public function maybe_flush_rewrite_rules() {
        if (get_transient('oyic_secure_login_flush_rules')) {
            flush_rewrite_rules();
            delete_transient('oyic_secure_login_flush_rules');
        }
    }

    /**
     * Handle custom login page display
     * 
     * @since 1.0.0
     * @return void
     */
    public function handle_custom_login_page() {
        if (!get_query_var('oyic_secure_login')) {
            return;
        }

        // Set up login page environment
        $this->setup_login_environment();
        
        // Handle different login actions
        $action = get_query_var('login_action');
        
        switch ($action) {
            case 'logout':
                $this->handle_logout();
                break;
            case 'lostpassword':
            case 'retrievepassword':
                $this->handle_lost_password();
                break;
            case 'resetpass':
            case 'rp':
                $this->handle_reset_password();
                break;
            case 'register':
                $this->handle_registration();
                break;
            default:
                $this->display_login_page();
                break;
        }
        
        exit;
    }

    /**
     * Setup login page environment
     * 
     * @since 1.0.0
     * @return void
     */
    private function setup_login_environment() {
        // Set up WordPress login environment
        if (!defined('DONOTCACHEPAGE')) {
            define('DONOTCACHEPAGE', true);
        }
        
        // Prevent caching
        nocache_headers();
        
        // Set content type
        header('Content-Type: text/html; charset=' . get_bloginfo('charset'));
        
        // Load login-specific WordPress functions
        if (!function_exists('wp_login_form')) {
            require_once ABSPATH . 'wp-includes/general-template.php';
        }
    }

    /**
     * Display login page
     * 
     * @since 1.0.0
     * @return void
     */
    private function display_login_page() {
        // Get login parameters
        $redirect_to = $this->get_redirect_to();
        $login_type = $this->get_login_type();
        $errors = $this->get_login_errors();
        $messages = $this->get_login_messages();
        
        // Set up template variables
        $template_vars = array(
            'redirect_to' => $redirect_to,
            'login_type' => $login_type,
            'errors' => $errors,
            'messages' => $messages,
            'options' => $this->options,
            'custom_login_url' => oyic_secure_login_get_login_url(),
            'otp_enabled' => oyic_secure_login_is_otp_enabled(),
            'site_name' => get_bloginfo('name'),
            'site_url' => home_url(),
        );
        
        /**
         * Filter login page template variables
         * 
         * @since 1.0.0
         * @param array $template_vars Template variables
         */
        $template_vars = apply_filters('oyic_secure_login_template_vars', $template_vars);
        
        // Extract variables for template
        extract($template_vars);
        
        // Include login page template
        $template_file = $this->get_login_template();
        
        if (file_exists($template_file)) {
            include $template_file;
        } else {
            wp_die(__('Login template not found.', 'oyic-secure-login'));
        }
    }

    /**
     * Handle logout
     * 
     * @since 1.0.0
     * @return void
     */
    private function handle_logout() {
        $redirect_to = isset($_GET['redirect_to']) ? esc_url_raw($_GET['redirect_to']) : home_url();
        
        if (is_user_logged_in()) {
            wp_logout();
            
            oyic_secure_login_log_event('user_logout', 'User logged out via custom page', array(
                'redirect_to' => $redirect_to,
            ));
        }
        
        wp_safe_redirect(add_query_arg('loggedout', 'true', $redirect_to));
        exit;
    }

    /**
     * Handle lost password
     * 
     * @since 1.0.0
     * @return void
     */
    private function handle_lost_password() {
        // For now, redirect to WordPress default
        // This could be implemented as a custom template in the future
        wp_redirect(wp_lostpassword_url());
        exit;
    }

    /**
     * Handle password reset
     * 
     * @since 1.0.0
     * @return void
     */
    private function handle_reset_password() {
        // For now, redirect to WordPress default
        // This could be implemented as a custom template in the future
        $reset_url = add_query_arg(array(
            'action' => 'resetpass',
            'key' => $_GET['key'] ?? '',
            'login' => $_GET['login'] ?? '',
        ), wp_login_url());
        
        wp_redirect($reset_url);
        exit;
    }

    /**
     * Handle registration
     * 
     * @since 1.0.0
     * @return void
     */
    private function handle_registration() {
        if (!get_option('users_can_register')) {
            wp_redirect(oyic_secure_login_get_login_url());
            exit;
        }
        
        // For now, redirect to WordPress default
        // This could be implemented as a custom template in the future
        wp_redirect(wp_registration_url());
        exit;
    }

    /**
     * Get redirect URL
     * 
     * @since 1.0.0
     * @return string Redirect URL
     */
    private function get_redirect_to() {
        $redirect_to = '';
        
        if (isset($_GET['redirect_to'])) {
            $redirect_to = esc_url_raw($_GET['redirect_to']);
        } elseif (isset($_POST['redirect_to'])) {
            $redirect_to = esc_url_raw($_POST['redirect_to']);
        }
        
        if (empty($redirect_to)) {
            $redirect_to = admin_url();
        }
        
        return $redirect_to;
    }

    /**
     * Get login type
     * 
     * @since 1.0.0
     * @return string Login type
     */
    private function get_login_type() {
        return isset($_GET['type']) ? sanitize_text_field($_GET['type']) : 'standard';
    }

    /**
     * Get login errors
     * 
     * @since 1.0.0
     * @return array Login errors
     */
    private function get_login_errors() {
        $errors = array();
        
        if (isset($_GET['error'])) {
            $error_code = sanitize_text_field($_GET['error']);
            $error_message = isset($_GET['message']) ? urldecode($_GET['message']) : '';
            
            switch ($error_code) {
                case 'login_failed':
                    $errors[] = $error_message ?: __('Invalid username or password.', 'oyic-secure-login');
                    break;
                case 'otp_invalid':
                    $errors[] = $error_message ?: __('Invalid or expired OTP code.', 'oyic-secure-login');
                    break;
                case 'rate_limited':
                    $errors[] = $error_message ?: __('Too many attempts. Please try again later.', 'oyic-secure-login');
                    break;
                case 'empty_credentials':
                    $errors[] = $error_message ?: __('Please enter your username and password.', 'oyic-secure-login');
                    break;
                default:
                    if (!empty($error_message)) {
                        $errors[] = $error_message;
                    }
                    break;
            }
        }
        
        return $errors;
    }

    /**
     * Get login messages
     * 
     * @since 1.0.0
     * @return array Login messages
     */
    private function get_login_messages() {
        $messages = array();
        
        if (isset($_GET['loggedout']) && $_GET['loggedout'] === 'true') {
            $messages[] = __('You have been logged out.', 'oyic-secure-login');
        }
        
        if (isset($_GET['registration']) && $_GET['registration'] === 'complete') {
            $messages[] = __('Registration complete. Please check your email.', 'oyic-secure-login');
        }
        
        return $messages;
    }

    /**
     * Get login template file
     * 
     * @since 1.0.0
     * @return string Template file path
     */
    private function get_login_template() {
        // Check for theme override first
        $theme_template = locate_template('oyic-secure-login/login-page.php');
        
        if ($theme_template) {
            return $theme_template;
        }
        
        // Use plugin template
        return OYIC_SECURE_LOGIN_PLUGIN_DIR . 'templates/login-page.php';
    }

    /**
     * Enqueue frontend scripts and styles
     * 
     * @since 1.0.0
     * @return void
     */
    public function enqueue_scripts() {
        if (!get_query_var('oyic_secure_login')) {
            return;
        }
        
        // Enqueue jQuery
        wp_enqueue_script('jquery');
        
        // Enqueue login scripts
        wp_enqueue_script(
            'oyic-secure-login',
            OYIC_SECURE_LOGIN_PLUGIN_URL . 'assets/secure-login.js',
            array('jquery'),
            OYIC_SECURE_LOGIN_VERSION,
            true
        );
        
        // Localize script
        wp_localize_script('oyic-secure-login', 'oyicSecureLogin', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'sendOtpNonce' => wp_create_nonce('oyic_send_otp'),
            'verifyOtpNonce' => wp_create_nonce('oyic_verify_otp'),
            'strings' => array(
                'sending' => __('Sending...', 'oyic-secure-login'),
                'verifying' => __('Verifying...', 'oyic-secure-login'),
                'expired' => __('Code expired', 'oyic-secure-login'),
                'networkError' => __('Network error. Please try again.', 'oyic-secure-login'),
                'invalidCode' => __('Please enter a valid 6-digit code.', 'oyic-secure-login'),
            )
        ));
        
        // Enqueue login styles
        wp_enqueue_style(
            'oyic-secure-login',
            OYIC_SECURE_LOGIN_PLUGIN_URL . 'assets/secure-login.css',
            array(),
            OYIC_SECURE_LOGIN_VERSION
        );
        
        // Add custom CSS for theme compatibility
        $this->add_inline_styles();
    }

    /**
     * Add inline styles for theme compatibility
     * 
     * @since 1.0.0
     * @return void
     */
    private function add_inline_styles() {
        $custom_css = "
            .oyic-login-page {
                background: #f1f1f1;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }
            
            .oyic-login-container {
                background: white;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                width: 100%;
                max-width: 400px;
            }
            
            .oyic-login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .oyic-login-header h1 {
                margin: 0 0 10px 0;
                font-size: 24px;
                color: #333;
            }
            
            .oyic-login-form .form-group {
                margin-bottom: 20px;
            }
            
            .oyic-login-form label {
                display: block;
                margin-bottom: 5px;
                font-weight: 500;
                color: #555;
            }
            
            .oyic-login-form input[type='text'],
            .oyic-login-form input[type='email'],
            .oyic-login-form input[type='password'] {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            
            .oyic-login-form input:focus {
                outline: none;
                border-color: #0073aa;
                box-shadow: 0 0 0 2px rgba(0,115,170,0.1);
            }
            
            .oyic-login-button {
                width: 100%;
                padding: 12px;
                background: #0073aa;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 16px;
                cursor: pointer;
                transition: background-color 0.3s;
            }
            
            .oyic-login-button:hover {
                background: #005a87;
            }
            
            .oyic-login-button:disabled {
                background: #ccc;
                cursor: not-allowed;
            }
            
            .oyic-login-tabs {
                display: flex;
                margin-bottom: 20px;
                border-bottom: 1px solid #ddd;
            }
            
            .oyic-tab-button {
                flex: 1;
                padding: 10px;
                background: none;
                border: none;
                cursor: pointer;
                border-bottom: 2px solid transparent;
                transition: all 0.3s;
            }
            
            .oyic-tab-button.active {
                border-bottom-color: #0073aa;
                color: #0073aa;
            }
            
            .oyic-login-form {
                display: none;
            }
            
            .oyic-login-form.active {
                display: block;
            }
            
            .oyic-error {
                background: #fee;
                color: #c33;
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 20px;
                border-left: 3px solid #c33;
            }
            
            .oyic-message {
                background: #efe;
                color: #363;
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 20px;
                border-left: 3px solid #363;
            }
            
            .oyic-otp-info {
                text-align: center;
                margin-top: 15px;
                font-size: 14px;
                color: #666;
            }
            
            .oyic-countdown {
                font-weight: bold;
                color: #0073aa;
            }
            
            .oyic-resend-link {
                color: #0073aa;
                text-decoration: none;
            }
            
            .oyic-resend-link:hover {
                text-decoration: underline;
            }
            
            @media (max-width: 480px) {
                .oyic-login-container {
                    margin: 20px;
                    padding: 30px 20px;
                }
            }
        ";
        
        wp_add_inline_style('oyic-secure-login', $custom_css);
    }

    /**
     * Customize login URL
     * 
     * @since 1.0.0
     * @param string $login_url Login URL
     * @param string $redirect Redirect URL
     * @param bool $force_reauth Force reauth
     * @return string Modified login URL
     */
    public function custom_login_url($login_url, $redirect = '', $force_reauth = false) {
        if (!oyic_secure_login_is_custom_login_enabled()) {
            return $login_url;
        }
        
        $custom_url = oyic_secure_login_get_login_url();
        
        if (!empty($redirect)) {
            $custom_url = add_query_arg('redirect_to', urlencode($redirect), $custom_url);
        }
        
        if ($force_reauth) {
            $custom_url = add_query_arg('reauth', '1', $custom_url);
        }
        
        return $custom_url;
    }

    /**
     * Customize logout URL
     * 
     * @since 1.0.0
     * @param string $logout_url Logout URL
     * @param string $redirect Redirect URL
     * @return string Modified logout URL
     */
    public function custom_logout_url($logout_url, $redirect = '') {
        if (!oyic_secure_login_is_custom_login_enabled()) {
            return $logout_url;
        }
        
        $custom_url = oyic_secure_login_get_login_url(array('action' => 'logout'));
        $custom_url = wp_nonce_url($custom_url, 'log-out');
        
        if (!empty($redirect)) {
            $custom_url = add_query_arg('redirect_to', urlencode($redirect), $custom_url);
        }
        
        return $custom_url;
    }

    /**
     * Add body classes for custom login page
     * 
     * @since 1.0.0
     * @param array $classes Body classes
     * @return array Modified body classes
     */
    public function add_body_classes($classes) {
        if (get_query_var('oyic_secure_login')) {
            $classes[] = 'oyic-login-page';
            $classes[] = 'login';
        }
        
        return $classes;
    }

    /**
     * Customize login page title
     * 
     * @since 1.0.0
     * @param string $title Page title
     * @param string $sep Title separator
     * @return string Modified title
     */
    public function custom_login_title($title, $sep = '') {
        if (get_query_var('oyic_secure_login')) {
            return __('Login', 'oyic-secure-login') . ' ' . $sep . ' ' . get_bloginfo('name');
        }
        
        return $title;
    }

    /**
     * Customize login page title parts
     * 
     * @since 1.0.0
     * @param array $title_parts Title parts
     * @return array Modified title parts
     */
    public function custom_login_title_parts($title_parts) {
        if (get_query_var('oyic_secure_login')) {
            $title_parts['title'] = __('Login', 'oyic-secure-login');
        }
        
        return $title_parts;
    }

    /**
     * Get current login URL
     * 
     * @since 1.0.0
     * @return string Current login URL
     */
    public function get_current_login_url() {
        return oyic_secure_login_get_login_url();
    }

    /**
     * Check if current page is custom login page
     * 
     * @since 1.0.0
     * @return bool True if custom login page
     */
    public function is_custom_login_page() {
        return (bool) get_query_var('oyic_secure_login');
    }
}
