<?php
/**
 * Test Helper Functions for OYIC Secure Login
 * 
 * @package OYIC\SecureLogin\Tests
 * @since 1.0.0
 */

namespace OYIC\SecureLogin\Tests;

/**
 * Test helper class
 */
class TestHelpers {

    /**
     * Generate random email address
     * 
     * @return string Random email
     */
    public static function random_email() {
        return 'test_' . wp_generate_password(8, false) . '@example.com';
    }

    /**
     * Generate random username
     * 
     * @return string Random username
     */
    public static function random_username() {
        return 'user_' . wp_generate_password(8, false);
    }

    /**
     * Generate random IP address
     * 
     * @return string Random IP
     */
    public static function random_ip() {
        return rand(1, 255) . '.' . rand(1, 255) . '.' . rand(1, 255) . '.' . rand(1, 255);
    }

    /**
     * Create test user with specific role
     * 
     * @param string $role User role
     * @return int User ID
     */
    public static function create_test_user($role = 'subscriber') {
        $user_id = wp_create_user(
            self::random_username(),
            'testpass123',
            self::random_email()
        );

        if (!is_wp_error($user_id)) {
            $user = new \WP_User($user_id);
            $user->set_role($role);
        }

        return $user_id;
    }

    /**
     * Mock WordPress environment for testing
     * 
     * @param array $args Environment arguments
     */
    public static function mock_wp_environment($args = array()) {
        $defaults = array(
            'is_admin' => false,
            'is_ajax' => false,
            'current_user_id' => 0,
            'request_method' => 'GET',
            'request_uri' => '/',
            'user_agent' => 'Mozilla/5.0 (Test Browser)',
            'remote_addr' => '127.0.0.1',
        );

        $args = wp_parse_args($args, $defaults);

        // Mock global variables
        if ($args['is_admin']) {
            set_current_screen('dashboard');
        }

        if ($args['is_ajax']) {
            define('DOING_AJAX', true);
        }

        if ($args['current_user_id']) {
            wp_set_current_user($args['current_user_id']);
        }

        // Mock $_SERVER variables
        $_SERVER['REQUEST_METHOD'] = $args['request_method'];
        $_SERVER['REQUEST_URI'] = $args['request_uri'];
        $_SERVER['HTTP_USER_AGENT'] = $args['user_agent'];
        $_SERVER['REMOTE_ADDR'] = $args['remote_addr'];
    }

    /**
     * Clean up WordPress environment after test
     */
    public static function cleanup_wp_environment() {
        wp_set_current_user(0);
        
        // Clean up $_SERVER
        unset($_SERVER['REQUEST_METHOD']);
        unset($_SERVER['REQUEST_URI']);
        unset($_SERVER['HTTP_USER_AGENT']);
        unset($_SERVER['REMOTE_ADDR']);
        
        // Clean up constants
        if (defined('DOING_AJAX')) {
            // Can't undefine constants, but we can work around it
        }
    }

    /**
     * Generate test OTP code
     * 
     * @return string 6-digit OTP code
     */
    public static function generate_test_otp() {
        return str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Create mock HTTP request
     * 
     * @param string $url Request URL
     * @param array $args Request arguments
     * @return array Mock response
     */
    public static function mock_http_request($url, $args = array()) {
        return array(
            'response' => array(
                'code' => 200,
                'message' => 'OK'
            ),
            'body' => json_encode(array('success' => true)),
            'headers' => array(),
            'cookies' => array()
        );
    }

    /**
     * Assert array contains specific keys
     * 
     * @param array $expected_keys Expected keys
     * @param array $array Array to check
     * @param string $message Assertion message
     */
    public static function assert_array_has_keys($expected_keys, $array, $message = '') {
        foreach ($expected_keys as $key) {
            if (!array_key_exists($key, $array)) {
                throw new \PHPUnit\Framework\AssertionFailedError(
                    $message ?: "Array does not contain expected key: {$key}"
                );
            }
        }
    }

    /**
     * Get plugin option with fallback
     * 
     * @param string $key Option key
     * @param mixed $default Default value
     * @return mixed Option value
     */
    public static function get_plugin_option($key, $default = null) {
        $options = get_option('oyic_secure_login_options', array());
        return isset($options[$key]) ? $options[$key] : $default;
    }

    /**
     * Set plugin option
     * 
     * @param string $key Option key
     * @param mixed $value Option value
     */
    public static function set_plugin_option($key, $value) {
        $options = get_option('oyic_secure_login_options', array());
        $options[$key] = $value;
        update_option('oyic_secure_login_options', $options);
    }

    /**
     * Simulate form submission
     * 
     * @param array $data Form data
     * @param string $nonce_action Nonce action
     * @return array Simulated $_POST data
     */
    public static function simulate_form_submission($data, $nonce_action = '') {
        $post_data = $data;
        
        if ($nonce_action) {
            $post_data['_wpnonce'] = wp_create_nonce($nonce_action);
        }
        
        return $post_data;
    }

    /**
     * Create temporary file for testing
     * 
     * @param string $content File content
     * @param string $extension File extension
     * @return string File path
     */
    public static function create_temp_file($content = '', $extension = 'txt') {
        $temp_file = tempnam(sys_get_temp_dir(), 'oyic_test_') . '.' . $extension;
        file_put_contents($temp_file, $content);
        return $temp_file;
    }

    /**
     * Clean up temporary files
     * 
     * @param array $files Array of file paths to delete
     */
    public static function cleanup_temp_files($files) {
        foreach ($files as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }

    /**
     * Mock email sending
     * 
     * @param bool $should_succeed Whether email should succeed
     */
    public static function mock_email_sending($should_succeed = true) {
        // Mock wp_mail function
        if (!function_exists('wp_mail_mock')) {
            function wp_mail_mock($to, $subject, $message, $headers = '', $attachments = array()) {
                global $wp_mail_mock_result;
                return $wp_mail_mock_result;
            }
        }
        
        global $wp_mail_mock_result;
        $wp_mail_mock_result = $should_succeed;
        
        // Replace wp_mail with mock
        add_filter('pre_wp_mail', function($null, $atts) use ($should_succeed) {
            return $should_succeed;
        }, 10, 2);
    }

    /**
     * Get current WordPress version for compatibility testing
     * 
     * @return string WordPress version
     */
    public static function get_wp_version() {
        global $wp_version;
        return $wp_version;
    }

    /**
     * Check if current PHP version meets requirement
     * 
     * @param string $required_version Required PHP version
     * @return bool True if requirement met
     */
    public static function php_version_meets_requirement($required_version) {
        return version_compare(PHP_VERSION, $required_version, '>=');
    }

    /**
     * Generate test database data
     * 
     * @param int $count Number of records to generate
     * @return array Test data
     */
    public static function generate_test_data($count = 10) {
        $data = array();
        
        for ($i = 0; $i < $count; $i++) {
            $data[] = array(
                'email' => self::random_email(),
                'otp_code' => self::generate_test_otp(),
                'created_at' => current_time('mysql'),
                'expires_at' => date('Y-m-d H:i:s', time() + 600), // 10 minutes
                'ip_address' => self::random_ip(),
                'user_agent' => 'Test User Agent ' . $i,
            );
        }
        
        return $data;
    }

    /**
     * Validate email format
     * 
     * @param string $email Email to validate
     * @return bool True if valid
     */
    public static function is_valid_email($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Validate OTP code format
     * 
     * @param string $code OTP code to validate
     * @return bool True if valid
     */
    public static function is_valid_otp_code($code) {
        return preg_match('/^\d{6}$/', $code);
    }

    /**
     * Create test WordPress hook
     * 
     * @param string $hook_name Hook name
     * @param callable $callback Callback function
     * @param int $priority Hook priority
     */
    public static function create_test_hook($hook_name, $callback, $priority = 10) {
        add_action($hook_name, $callback, $priority);
    }

    /**
     * Remove test WordPress hook
     * 
     * @param string $hook_name Hook name
     * @param callable $callback Callback function
     * @param int $priority Hook priority
     */
    public static function remove_test_hook($hook_name, $callback, $priority = 10) {
        remove_action($hook_name, $callback, $priority);
    }
}
