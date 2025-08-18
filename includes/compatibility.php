<?php
/**
 * Compatibility Functions for OYIC Secure Login
 * 
 * This file contains functions that provide backward compatibility
 * and handle various WordPress versions and environments.
 * 
 * @package OYIC\SecureLogin
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Polyfill for wp_json_encode for older WordPress versions
 * 
 * @since 1.0.0
 * @param mixed $data Data to encode
 * @param int $options JSON encode options
 * @param int $depth Maximum depth
 * @return string|false JSON string or false on failure
 */
if (!function_exists('wp_json_encode')) {
    function wp_json_encode($data, $options = 0, $depth = 512) {
        return json_encode($data, $options, $depth);
    }
}

/**
 * Polyfill for wp_rand for older WordPress versions
 * 
 * @since 1.0.0
 * @param int $min Minimum value
 * @param int $max Maximum value
 * @return int Random number
 */
if (!function_exists('wp_rand')) {
    function wp_rand($min = null, $max = null) {
        global $rnd_value;

        // Some misconfigured 32bit environments (Entropy PHP, for example)
        // truncate integers larger than PHP_INT_MAX to PHP_INT_MAX rather than overflowing them to floats.
        $max_random_number = 3000000;

        if (is_null($min)) {
            $min = 0;
        }

        if (is_null($max)) {
            $max = $max_random_number;
        }

        // We only handle Ints, floats are truncated to their integer value.
        $min = (int) $min;
        $max = (int) $max;

        // Use PHP's CSPRNG, or a compatible method
        static $use_random_int_functionality = true;
        if ($use_random_int_functionality) {
            try {
                $_max = (0 != $min) ? $max - $min : $max;
                $_max += 1;
                $_max = max($_max, 1);
                $_random = random_int(0, $_max - 1);
                return absint($_random + $min);
            } catch (Exception $e) {
                $use_random_int_functionality = false;
            }
        }

        // If this platform does not have a Cryptographically Secure PRNG, we'll use mt_rand().
        if (is_null($rnd_value)) {
            if (function_exists('microtime')) {
                $seed = microtime() . uniqid(mt_rand(), true);
            } else {
                $seed = uniqid(mt_rand(), true);
            }
            $rnd_value = crc32($seed);
        }

        $value = abs(crc32($rnd_value . microtime()));
        $value = $value % ($max - $min + 1);
        $rnd_value = md5($rnd_value . $value . microtime());

        return intval($value + $min);
    }
}

/**
 * Polyfill for wp_generate_password for older WordPress versions
 * 
 * @since 1.0.0
 * @param int $length Password length
 * @param bool $special_chars Include special characters
 * @param bool $extra_special_chars Include extra special characters
 * @return string Generated password
 */
if (!function_exists('wp_generate_password')) {
    function wp_generate_password($length = 12, $special_chars = true, $extra_special_chars = false) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        if ($special_chars) {
            $chars .= '!@#$%^&*()';
        }
        if ($extra_special_chars) {
            $chars .= '-_ []{}<>~`+=,.;:/?|';
        }

        $password = '';
        for ($i = 0; $i < $length; $i++) {
            $password .= substr($chars, wp_rand(0, strlen($chars) - 1), 1);
        }

        return $password;
    }
}

/**
 * Polyfill for wp_hash_password for older WordPress versions
 * 
 * @since 1.0.0
 * @param string $password Password to hash
 * @return string Hashed password
 */
if (!function_exists('wp_hash_password')) {
    function wp_hash_password($password) {
        if (function_exists('password_hash')) {
            return password_hash($password, PASSWORD_DEFAULT);
        }
        
        // Fallback to WordPress's built-in hasher
        global $wp_hasher;

        if (empty($wp_hasher)) {
            require_once ABSPATH . WPINC . '/class-phpass.php';
            $wp_hasher = new PasswordHash(8, true);
        }

        return $wp_hasher->HashPassword(trim($password));
    }
}

/**
 * Polyfill for wp_check_password for older WordPress versions
 * 
 * @since 1.0.0
 * @param string $password Plaintext password
 * @param string $hash Hash to check against
 * @param string|int $user_id User ID (optional)
 * @return bool True if password matches hash
 */
if (!function_exists('wp_check_password')) {
    function wp_check_password($password, $hash, $user_id = '') {
        if (function_exists('password_verify') && strpos($hash, '$2y$') === 0) {
            return password_verify($password, $hash);
        }
        
        // Fallback to WordPress's built-in hasher
        global $wp_hasher;

        if (empty($wp_hasher)) {
            require_once ABSPATH . WPINC . '/class-phpass.php';
            $wp_hasher = new PasswordHash(8, true);
        }

        $check = $wp_hasher->CheckPassword($password, $hash);

        return apply_filters('check_password', $check, $password, $hash, $user_id);
    }
}

// Note: wp_safe_redirect and wp_sanitize_redirect are available in WordPress 2.8+
// Since we require WordPress 5.0+, these functions are always available

/**
 * Compatibility function for current_time with UTC support
 * 
 * @since 1.0.0
 * @param string $type Type of time (mysql, timestamp, etc.)
 * @param bool $gmt Whether to use GMT
 * @return string|int Current time
 */
function oyic_secure_login_current_time($type, $gmt = false) {
    if (function_exists('current_time')) {
        return current_time($type, $gmt);
    }
    
    // Fallback implementation
    switch ($type) {
        case 'mysql':
            return $gmt ? gmdate('Y-m-d H:i:s') : date('Y-m-d H:i:s');
        case 'timestamp':
            return $gmt ? time() : (time() + (get_option('gmt_offset') * HOUR_IN_SECONDS));
        default:
            return $gmt ? gmdate($type) : date($type);
    }
}

// wp_doing_ajax is available in WordPress 4.7+ (we require 5.0+)

// wp_doing_cron is available in WordPress 4.8+ (we require 5.0+)

// is_user_logged_in is available in WordPress 2.0+ (we require 5.0+)

// get_current_user_id is available in WordPress 3.0+ (we require 5.0+)

// wp_unslash is available in WordPress 3.6+ (we require 5.0+)

// wp_slash is available in WordPress 3.6+ (we require 5.0+)

// wp_parse_args is available in WordPress 2.2+ (we require 5.0+)

/**
 * Compatibility check for minimum WordPress version
 * 
 * @since 1.0.0
 * @param string $min_version Minimum required version
 * @return bool True if WordPress version is sufficient
 */
function oyic_secure_login_check_wp_version($min_version = '5.0') {
    global $wp_version;
    return version_compare($wp_version, $min_version, '>=');
}

/**
 * Compatibility check for minimum PHP version
 * 
 * @since 1.0.0
 * @param string $min_version Minimum required version
 * @return bool True if PHP version is sufficient
 */
function oyic_secure_login_check_php_version($min_version = '7.4') {
    return version_compare(PHP_VERSION, $min_version, '>=');
}

/**
 * Check if required WordPress functions exist
 * 
 * @since 1.0.0
 * @return array Missing functions
 */
function oyic_secure_login_check_required_functions() {
    $required_functions = array(
        'add_action',
        'add_filter',
        'wp_enqueue_script',
        'wp_enqueue_style',
        'wp_localize_script',
        'wp_create_nonce',
        'wp_verify_nonce',
        'sanitize_text_field',
        'sanitize_email',
        'esc_html',
        'esc_attr',
        'esc_url',
        'wp_mail',
        'get_option',
        'update_option',
        'delete_option',
    );

    $missing_functions = array();
    
    foreach ($required_functions as $function) {
        if (!function_exists($function)) {
            $missing_functions[] = $function;
        }
    }

    return $missing_functions;
}

/**
 * Check if required WordPress constants are defined
 * 
 * @since 1.0.0
 * @return array Missing constants
 */
function oyic_secure_login_check_required_constants() {
    $required_constants = array(
        'ABSPATH',
        'WPINC',
        'WP_CONTENT_DIR',
        'WP_PLUGIN_DIR',
    );

    $missing_constants = array();
    
    foreach ($required_constants as $constant) {
        if (!defined($constant)) {
            $missing_constants[] = $constant;
        }
    }

    return $missing_constants;
}

// wp_strip_all_tags is available in WordPress 2.9+ (we require 5.0+)
// wp_kses_post is available in WordPress 2.9+ (we require 5.0+)

/**
 * Check if the current WordPress installation supports the plugin
 * 
 * @since 1.0.0
 * @return array Compatibility check results
 */
function oyic_secure_login_compatibility_check() {
    $results = array(
        'wp_version_ok' => oyic_secure_login_check_wp_version('5.0'),
        'php_version_ok' => oyic_secure_login_check_php_version('7.4'),
        'missing_functions' => oyic_secure_login_check_required_functions(),
        'missing_constants' => oyic_secure_login_check_required_constants(),
        'multisite' => is_multisite(),
        'ssl_enabled' => is_ssl(),
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time'),
    );

    $results['compatible'] = $results['wp_version_ok'] && 
                            $results['php_version_ok'] && 
                            empty($results['missing_functions']) && 
                            empty($results['missing_constants']);

    return $results;
}

/**
 * Display compatibility warnings in admin
 * 
 * @since 1.0.0
 * @return void
 */
function oyic_secure_login_compatibility_warnings() {
    // Don't show during plugin activation/deactivation
    if (isset($_GET['activate']) || isset($_GET['deactivate']) || 
        (defined('DOING_AJAX') && DOING_AJAX) ||
        (defined('DOING_CRON') && DOING_CRON)) {
        return;
    }
    
    $check = oyic_secure_login_compatibility_check();
    
    if (!$check['compatible']) {
        echo '<div class="notice notice-error"><p>';
        echo '<strong>' . esc_html__('OYIC Secure Login Compatibility Issues:', 'oyic-secure-login') . '</strong><br>';
        
        if (!$check['wp_version_ok']) {
            echo esc_html__('WordPress version is too old. Please update to version 5.0 or higher.', 'oyic-secure-login') . '<br>';
        }
        
        if (!$check['php_version_ok']) {
            echo esc_html__('PHP version is too old. Please update to PHP 7.4 or higher.', 'oyic-secure-login') . '<br>';
        }
        
        if (!empty($check['missing_functions'])) {
            echo esc_html__('Missing required functions: ', 'oyic-secure-login') . implode(', ', $check['missing_functions']) . '<br>';
        }
        
        if (!empty($check['missing_constants'])) {
            echo esc_html__('Missing required constants: ', 'oyic-secure-login') . implode(', ', $check['missing_constants']) . '<br>';
        }
        
        echo '</p></div>';
    }
}

// Run compatibility check on admin pages (but not during activation)
if (is_admin() && !isset($_GET['activate']) && !isset($_GET['deactivate'])) {
    add_action('admin_notices', 'oyic_secure_login_compatibility_warnings');
}
