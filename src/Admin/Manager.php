<?php
/**
 * Admin Manager Class
 * 
 * Handles all admin-related functionality including settings pages,
 * admin notices, dashboard widgets, and admin-only features.
 * 
 * @package OYIC\SecureLogin\Admin
 * @since 1.0.0
 */

namespace OYIC\SecureLogin\Admin;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Admin Manager
 * 
 * Manages all admin interface functionality for the plugin.
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
        
        // Debug: Log admin manager initialization
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Admin Manager: Constructor called');
        }
        
        $this->init();
        
        // Debug: Log admin manager initialization complete
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Admin Manager: Initialization complete');
        }
    }

    /**
     * Initialize admin functionality
     * 
     * @since 1.0.0
     * @return void
     */
    private function init() {
        // Add admin menu
        add_action('admin_menu', array($this, 'add_admin_menu'));
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Add admin notices
        add_action('admin_notices', array($this, 'admin_notices'));
        
        // Add plugin action links
        add_filter('plugin_action_links_' . OYIC_SECURE_LOGIN_PLUGIN_BASENAME, array($this, 'plugin_action_links'));
        
        // Add admin scripts and styles
        add_action('admin_enqueue_scripts', array($this, 'admin_enqueue_scripts'));
        
        // Handle AJAX requests
        add_action('wp_ajax_oyic_test_email', array($this, 'test_email_ajax'));
        add_action('wp_ajax_oyic_flush_rules', array($this, 'flush_rules_ajax'));
        add_action('wp_ajax_oyic_generate_key', array($this, 'generate_key_ajax'));
        
        // Add dashboard widget
        add_action('wp_dashboard_setup', array($this, 'add_dashboard_widget'));
        
        // Handle settings updates
        add_action('update_option_oyic_secure_login_options', array($this, 'handle_settings_update'), 10, 2);
    }

    /**
     * Add admin menu
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_admin_menu() {
        // Debug: Log menu registration
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Admin Manager: Adding admin menu');
        }
        
        $hook = add_options_page(
            __('OYIC Secure Login Settings', 'oyic-secure-login'),
            __('Secure Login', 'oyic-secure-login'),
            'manage_options',
            'oyic-secure-login',
            array($this, 'admin_page')
        );
        
        // Debug: Log menu hook result
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Admin Manager: Menu hook result: ' . ($hook ? $hook : 'FAILED'));
        }
    }

    /**
     * Register plugin settings
     * 
     * @since 1.0.0
     * @return void
     */
    public function register_settings() {
        register_setting(
            'oyic_secure_login_settings',
            'oyic_secure_login_options',
            array($this, 'sanitize_options')
        );

        // Main settings section
        add_settings_section(
            'oyic_secure_login_main',
            __('Security Settings', 'oyic-secure-login'),
            array($this, 'main_section_callback'),
            'oyic-secure-login'
        );

        // Custom login URL settings
        add_settings_field(
            'enable_custom_login',
            __('Enable Custom Login URL', 'oyic-secure-login'),
            array($this, 'enable_custom_login_callback'),
            'oyic-secure-login',
            'oyic_secure_login_main'
        );

        add_settings_field(
            'custom_login_slug',
            __('Custom Login Slug', 'oyic-secure-login'),
            array($this, 'custom_login_slug_callback'),
            'oyic-secure-login',
            'oyic_secure_login_main'
        );

        add_settings_field(
            'override_key',
            __('Emergency Override Key', 'oyic-secure-login'),
            array($this, 'override_key_callback'),
            'oyic-secure-login',
            'oyic_secure_login_main'
        );

        // OTP settings section
        add_settings_section(
            'oyic_secure_login_otp',
            __('OTP Authentication Settings', 'oyic-secure-login'),
            array($this, 'otp_section_callback'),
            'oyic-secure-login'
        );

        add_settings_field(
            'enable_otp_login',
            __('Enable OTP Login', 'oyic-secure-login'),
            array($this, 'enable_otp_login_callback'),
            'oyic-secure-login',
            'oyic_secure_login_otp'
        );

        add_settings_field(
            'otp_expiry_minutes',
            __('OTP Expiry Time', 'oyic-secure-login'),
            array($this, 'otp_expiry_callback'),
            'oyic-secure-login',
            'oyic_secure_login_otp'
        );

        add_settings_field(
            'email_from_name',
            __('Email From Name', 'oyic-secure-login'),
            array($this, 'email_from_name_callback'),
            'oyic-secure-login',
            'oyic_secure_login_otp'
        );

        add_settings_field(
            'email_from_address',
            __('Email From Address', 'oyic-secure-login'),
            array($this, 'email_from_address_callback'),
            'oyic-secure-login',
            'oyic_secure_login_otp'
        );

        // Rate limiting section
        add_settings_section(
            'oyic_secure_login_rate_limit',
            __('Rate Limiting Settings', 'oyic-secure-login'),
            array($this, 'rate_limit_section_callback'),
            'oyic-secure-login'
        );

        add_settings_field(
            'rate_limit_attempts',
            __('Max Attempts', 'oyic-secure-login'),
            array($this, 'rate_limit_attempts_callback'),
            'oyic-secure-login',
            'oyic_secure_login_rate_limit'
        );

        add_settings_field(
            'rate_limit_window',
            __('Time Window', 'oyic-secure-login'),
            array($this, 'rate_limit_window_callback'),
            'oyic-secure-login',
            'oyic_secure_login_rate_limit'
        );
    }

    /**
     * Sanitize plugin options
     * 
     * @since 1.0.0
     * @param array $input Raw input data
     * @return array Sanitized options
     */
    public function sanitize_options($input) {
        $sanitized = array();

        // Boolean options
        $boolean_options = array(
            'enable_custom_login',
            'enable_otp_login'
        );

        foreach ($boolean_options as $option) {
            $sanitized[$option] = !empty($input[$option]);
        }

        // Text options
        $sanitized['custom_login_slug'] = oyic_secure_login_sanitize_slug(
            isset($input['custom_login_slug']) ? $input['custom_login_slug'] : 'secure-access'
        );

        $sanitized['override_key'] = sanitize_text_field(
            isset($input['override_key']) ? $input['override_key'] : wp_generate_password(16, false)
        );

        $sanitized['email_from_name'] = sanitize_text_field(
            isset($input['email_from_name']) ? $input['email_from_name'] : get_bloginfo('name')
        );

        $sanitized['email_from_address'] = sanitize_email(
            isset($input['email_from_address']) ? $input['email_from_address'] : get_option('admin_email')
        );

        // Numeric options
        $sanitized['otp_expiry_minutes'] = absint(
            isset($input['otp_expiry_minutes']) ? $input['otp_expiry_minutes'] : 10
        );

        $sanitized['rate_limit_attempts'] = absint(
            isset($input['rate_limit_attempts']) ? $input['rate_limit_attempts'] : 3
        );

        $sanitized['rate_limit_window'] = absint(
            isset($input['rate_limit_window']) ? $input['rate_limit_window'] : 5
        );

        // Validate ranges
        $sanitized['otp_expiry_minutes'] = max(1, min(60, $sanitized['otp_expiry_minutes']));
        $sanitized['rate_limit_attempts'] = max(1, min(20, $sanitized['rate_limit_attempts']));
        $sanitized['rate_limit_window'] = max(1, min(60, $sanitized['rate_limit_window']));

        return $sanitized;
    }

    /**
     * Admin page callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function admin_page() {
        // Debug: Log admin page access
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Admin Manager: admin_page() called');
            error_log('OYIC Admin Manager: User can manage_options: ' . (current_user_can('manage_options') ? 'YES' : 'NO'));
        }
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'oyic-secure-login'));
        }

        $template_path = OYIC_SECURE_LOGIN_PLUGIN_DIR . 'templates/admin-page.php';
        
        // Debug: Log template info
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('OYIC Admin Manager: Template path: ' . $template_path);
            error_log('OYIC Admin Manager: Template exists: ' . (file_exists($template_path) ? 'YES' : 'NO'));
        }
        
        if (file_exists($template_path)) {
            include $template_path;
        } else {
            echo '<div class="wrap"><h1>OYIC Secure Login Settings</h1>';
            echo '<div class="error"><p>Template file not found: ' . esc_html($template_path) . '</p></div>';
            echo '</div>';
        }
    }

    /**
     * Main section callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function main_section_callback() {
        echo '<p>' . esc_html__('Configure your custom login URL and security settings.', 'oyic-secure-login') . '</p>';
    }

    /**
     * OTP section callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function otp_section_callback() {
        echo '<p>' . esc_html__('Configure email-based one-time password authentication.', 'oyic-secure-login') . '</p>';
    }

    /**
     * Rate limit section callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function rate_limit_section_callback() {
        echo '<p>' . esc_html__('Configure rate limiting to prevent brute force attacks.', 'oyic-secure-login') . '</p>';
    }

    /**
     * Enable custom login callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function enable_custom_login_callback() {
        $enabled = !empty($this->options['enable_custom_login']);
        echo '<input type="checkbox" name="oyic_secure_login_options[enable_custom_login]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . esc_html__('Block access to wp-login.php and redirect to custom URL.', 'oyic-secure-login') . '</p>';
        echo '<p class="description" style="color: #d63384;"><strong>' . esc_html__('Warning: Make sure to test your custom login URL before enabling this option!', 'oyic-secure-login') . '</strong></p>';
    }

    /**
     * Custom login slug callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function custom_login_slug_callback() {
        $slug = isset($this->options['custom_login_slug']) ? $this->options['custom_login_slug'] : 'secure-access';
        echo '<input type="text" name="oyic_secure_login_options[custom_login_slug]" value="' . esc_attr($slug) . '" class="regular-text" />';
        echo '<p class="description">' . sprintf(
            /* translators: %s: Example URL */
            esc_html__('Custom slug for login URL. Current URL: %s', 'oyic-secure-login'),
            '<code>' . esc_html(home_url('/' . $slug . '/')) . '</code>'
        ) . '</p>';
    }

    /**
     * Override key callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function override_key_callback() {
        $key = isset($this->options['override_key']) ? $this->options['override_key'] : '';
        echo '<input type="text" name="oyic_secure_login_options[override_key]" value="' . esc_attr($key) . '" class="regular-text" readonly />';
        echo '<button type="button" class="button" onclick="generateOverrideKey()">' . esc_html__('Generate New Key', 'oyic-secure-login') . '</button>';
        echo '<p class="description">' . sprintf(
            /* translators: %s: Example URL */
            esc_html__('Emergency access URL: %s', 'oyic-secure-login'),
            '<code>' . esc_html(wp_login_url() . '?override=' . $key) . '</code>'
        ) . '</p>';
        echo '<p class="description" style="color: #d63384;"><strong>' . esc_html__('Keep this key safe! You\'ll need it for emergency access.', 'oyic-secure-login') . '</strong></p>';
    }

    /**
     * Enable OTP login callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function enable_otp_login_callback() {
        $enabled = !empty($this->options['enable_otp_login']);
        echo '<input type="checkbox" name="oyic_secure_login_options[enable_otp_login]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . esc_html__('Allow users to login using email OTP (One-Time Password).', 'oyic-secure-login') . '</p>';
    }

    /**
     * OTP expiry callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function otp_expiry_callback() {
        $expiry = isset($this->options['otp_expiry_minutes']) ? $this->options['otp_expiry_minutes'] : 10;
        echo '<input type="number" name="oyic_secure_login_options[otp_expiry_minutes]" value="' . esc_attr($expiry) . '" min="1" max="60" class="small-text" />';
        echo ' ' . esc_html__('minutes', 'oyic-secure-login');
        echo '<p class="description">' . esc_html__('How long OTP codes remain valid (1-60 minutes).', 'oyic-secure-login') . '</p>';
    }

    /**
     * Email from name callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function email_from_name_callback() {
        $name = isset($this->options['email_from_name']) ? $this->options['email_from_name'] : get_bloginfo('name');
        echo '<input type="text" name="oyic_secure_login_options[email_from_name]" value="' . esc_attr($name) . '" class="regular-text" />';
        echo '<p class="description">' . esc_html__('Name that appears in OTP emails.', 'oyic-secure-login') . '</p>';
    }

    /**
     * Email from address callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function email_from_address_callback() {
        $address = isset($this->options['email_from_address']) ? $this->options['email_from_address'] : get_option('admin_email');
        echo '<input type="email" name="oyic_secure_login_options[email_from_address]" value="' . esc_attr($address) . '" class="regular-text" />';
        echo '<button type="button" class="button" onclick="testEmail()">' . esc_html__('Test Email', 'oyic-secure-login') . '</button>';
        echo '<p class="description">' . esc_html__('Email address that sends OTP codes.', 'oyic-secure-login') . '</p>';
    }

    /**
     * Rate limit attempts callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function rate_limit_attempts_callback() {
        $attempts = isset($this->options['rate_limit_attempts']) ? $this->options['rate_limit_attempts'] : 3;
        echo '<input type="number" name="oyic_secure_login_options[rate_limit_attempts]" value="' . esc_attr($attempts) . '" min="1" max="20" class="small-text" />';
        echo '<p class="description">' . esc_html__('Maximum OTP requests per time window (1-20).', 'oyic-secure-login') . '</p>';
    }

    /**
     * Rate limit window callback
     * 
     * @since 1.0.0
     * @return void
     */
    public function rate_limit_window_callback() {
        $window = isset($this->options['rate_limit_window']) ? $this->options['rate_limit_window'] : 5;
        echo '<input type="number" name="oyic_secure_login_options[rate_limit_window]" value="' . esc_attr($window) . '" min="1" max="60" class="small-text" />';
        echo ' ' . esc_html__('minutes', 'oyic-secure-login');
        echo '<p class="description">' . esc_html__('Time window for rate limiting (1-60 minutes).', 'oyic-secure-login') . '</p>';
    }

    /**
     * Add plugin action links
     * 
     * @since 1.0.0
     * @param array $links Existing links
     * @return array Modified links
     */
    public function plugin_action_links($links) {
        $settings_link = '<a href="' . admin_url('options-general.php?page=oyic-secure-login') . '">' . __('Settings', 'oyic-secure-login') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    /**
     * Admin notices
     * 
     * @since 1.0.0
     * @return void
     */
    public function admin_notices() {
        // Check if rewrite rules need flushing
        if (get_transient('oyic_secure_login_flush_rules')) {
            echo '<div class="notice notice-info is-dismissible">';
            echo '<p>' . esc_html__('OYIC Secure Login: Rewrite rules have been updated. Please test your custom login URL.', 'oyic-secure-login') . '</p>';
            echo '</div>';
            delete_transient('oyic_secure_login_flush_rules');
        }

        // Warning if custom login is enabled but no override key
        if (!empty($this->options['enable_custom_login']) && empty($this->options['override_key'])) {
            echo '<div class="notice notice-error">';
            echo '<p>' . sprintf(
                /* translators: %s: Settings page URL */
                esc_html__('OYIC Secure Login: No override key is set! Please configure one in %s to prevent lockout.', 'oyic-secure-login'),
                '<a href="' . admin_url('options-general.php?page=oyic-secure-login') . '">' . esc_html__('settings', 'oyic-secure-login') . '</a>'
            ) . '</p>';
            echo '</div>';
        }

        // Check if email function is available for OTP
        if (!empty($this->options['enable_otp_login']) && !function_exists('wp_mail')) {
            echo '<div class="notice notice-warning">';
            echo '<p>' . esc_html__('OYIC Secure Login: OTP login is enabled but wp_mail() function is not available. OTP emails may not work.', 'oyic-secure-login') . '</p>';
            echo '</div>';
        }
    }

    /**
     * Enqueue admin scripts and styles
     * 
     * @since 1.0.0
     * @param string $hook Current admin page hook
     * @return void
     */
    public function admin_enqueue_scripts($hook) {
        if ($hook !== 'settings_page_oyic-secure-login') {
            return;
        }

        wp_enqueue_script(
            'oyic-secure-login-admin',
            OYIC_SECURE_LOGIN_PLUGIN_URL . 'assets/admin.js',
            array('jquery'),
            OYIC_SECURE_LOGIN_VERSION,
            true
        );

        wp_localize_script('oyic-secure-login-admin', 'oyicSecureLoginAdmin', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('oyic_secure_login_admin'),
            'strings' => array(
                'testing' => __('Testing...', 'oyic-secure-login'),
                'testSuccess' => __('Test email sent successfully!', 'oyic-secure-login'),
                'testError' => __('Failed to send test email.', 'oyic-secure-login'),
                'generating' => __('Generating...', 'oyic-secure-login'),
                'confirmFlush' => __('This will flush WordPress rewrite rules. Continue?', 'oyic-secure-login'),
            )
        ));

        wp_enqueue_style(
            'oyic-secure-login-admin',
            OYIC_SECURE_LOGIN_PLUGIN_URL . 'assets/admin.css',
            array(),
            OYIC_SECURE_LOGIN_VERSION
        );
    }

    /**
     * Test email AJAX handler
     * 
     * @since 1.0.0
     * @return void
     */
    public function test_email_ajax() {
        check_ajax_referer('oyic_secure_login_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'oyic-secure-login'));
        }

        $email = get_option('admin_email');
        $subject = __('OYIC Secure Login - Test Email', 'oyic-secure-login');
        $message = __('This is a test email from OYIC Secure Login plugin. If you received this, email functionality is working correctly.', 'oyic-secure-login');

        $sent = wp_mail($email, $subject, $message);

        if ($sent) {
            wp_send_json_success(__('Test email sent successfully!', 'oyic-secure-login'));
        } else {
            wp_send_json_error(__('Failed to send test email.', 'oyic-secure-login'));
        }
    }

    /**
     * Flush rules AJAX handler
     * 
     * @since 1.0.0
     * @return void
     */
    public function flush_rules_ajax() {
        check_ajax_referer('oyic_secure_login_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'oyic-secure-login'));
        }

        flush_rewrite_rules();
        wp_send_json_success(__('Rewrite rules flushed successfully!', 'oyic-secure-login'));
    }

    /**
     * Generate key AJAX handler
     * 
     * @since 1.0.0
     * @return void
     */
    public function generate_key_ajax() {
        check_ajax_referer('oyic_secure_login_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'oyic-secure-login'));
        }

        $key = oyic_secure_login_generate_random_string(16);
        wp_send_json_success(array('key' => $key));
    }

    /**
     * Add dashboard widget
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_dashboard_widget() {
        if (current_user_can('manage_options')) {
            wp_add_dashboard_widget(
                'oyic_secure_login_dashboard',
                __('OYIC Secure Login Status', 'oyic-secure-login'),
                array($this, 'dashboard_widget_content')
            );
        }
    }

    /**
     * Dashboard widget content
     * 
     * @since 1.0.0
     * @return void
     */
    public function dashboard_widget_content() {
        $database_manager = oyic_secure_login()->get_component('database');
        $stats = $database_manager ? $database_manager->get_otp_statistics(7) : array();

        echo '<div class="oyic-dashboard-widget">';
        echo '<h4>' . esc_html__('Security Status', 'oyic-secure-login') . '</h4>';
        
        echo '<p>';
        if (!empty($this->options['enable_custom_login'])) {
            echo '<span style="color: green;">✓</span> ' . esc_html__('Custom login URL: Active', 'oyic-secure-login');
        } else {
            echo '<span style="color: orange;">⚠</span> ' . esc_html__('Custom login URL: Inactive', 'oyic-secure-login');
        }
        echo '</p>';

        echo '<p>';
        if (!empty($this->options['enable_otp_login'])) {
            echo '<span style="color: green;">✓</span> ' . esc_html__('OTP authentication: Active', 'oyic-secure-login');
        } else {
            echo '<span style="color: orange;">⚠</span> ' . esc_html__('OTP authentication: Inactive', 'oyic-secure-login');
        }
        echo '</p>';

        if (!empty($stats)) {
            echo '<h4>' . esc_html__('Last 7 Days', 'oyic-secure-login') . '</h4>';
            echo '<p>' . sprintf(
                /* translators: %d: Number of OTP requests */
                esc_html__('OTP requests: %d', 'oyic-secure-login'),
                $stats['total_requests']
            ) . '</p>';
            echo '<p>' . sprintf(
                /* translators: %d: Number of unique users */
                esc_html__('Unique users: %d', 'oyic-secure-login'),
                $stats['unique_emails']
            ) . '</p>';
        }

        echo '<p><a href="' . admin_url('options-general.php?page=oyic-secure-login') . '" class="button button-primary">' . esc_html__('Manage Settings', 'oyic-secure-login') . '</a></p>';
        echo '</div>';
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
        // Check if custom login slug changed
        $old_slug = isset($old_value['custom_login_slug']) ? $old_value['custom_login_slug'] : 'secure-access';
        $new_slug = isset($new_value['custom_login_slug']) ? $new_value['custom_login_slug'] : 'secure-access';

        if ($old_slug !== $new_slug) {
            // Schedule rewrite rules flush
            set_transient('oyic_secure_login_flush_rules', true, 60);
        }

        // Log configuration changes
        oyic_secure_login_log_event('settings_updated', 'Plugin settings were updated', array(
            'old_custom_login' => !empty($old_value['enable_custom_login']),
            'new_custom_login' => !empty($new_value['enable_custom_login']),
            'old_otp' => !empty($old_value['enable_otp_login']),
            'new_otp' => !empty($new_value['enable_otp_login']),
        ));
    }
}
