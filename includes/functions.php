<?php
/**
 * Helper Functions for OYIC Secure Login
 * 
 * This file contains global helper functions that can be used
 * throughout the plugin and by third-party developers.
 * 
 * @package OYIC\SecureLogin
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Get plugin option value
 * 
 * Convenience function to get a specific plugin option value.
 * 
 * @since 1.0.0
 * @param string $key Option key
 * @param mixed $default Default value if option doesn't exist
 * @return mixed Option value or default
 */
function oyic_secure_login_get_option($key, $default = null) {
    $plugin = oyic_secure_login();
    return $plugin->get_options($key) ?? $default;
}

/**
 * Update plugin option value
 * 
 * Convenience function to update a specific plugin option value.
 * 
 * @since 1.0.0
 * @param string $key Option key
 * @param mixed $value Option value
 * @return bool True on success, false on failure
 */
function oyic_secure_login_update_option($key, $value) {
    $plugin = oyic_secure_login();
    return $plugin->update_option($key, $value);
}

/**
 * Get custom login URL
 * 
 * Returns the custom login URL based on current settings.
 * 
 * @since 1.0.0
 * @param array $args Optional query arguments to append
 * @return string Custom login URL
 */
function oyic_secure_login_get_login_url($args = array()) {
    $slug = oyic_secure_login_get_option('custom_login_slug', 'secure-access');
    $url = home_url('/' . $slug . '/');
    
    if (!empty($args)) {
        $url = add_query_arg($args, $url);
    }
    
    return $url;
}

/**
 * Get override login URL
 * 
 * Returns the emergency override login URL.
 * 
 * @since 1.0.0
 * @return string Override login URL
 */
function oyic_secure_login_get_override_url() {
    $override_key = oyic_secure_login_get_option('override_key');
    return wp_login_url() . '?override=' . $override_key;
}

/**
 * Check if custom login is enabled
 * 
 * @since 1.0.0
 * @return bool True if enabled, false otherwise
 */
function oyic_secure_login_is_custom_login_enabled() {
    return (bool) oyic_secure_login_get_option('enable_custom_login', false);
}

/**
 * Check if OTP login is enabled
 * 
 * @since 1.0.0
 * @return bool True if enabled, false otherwise
 */
function oyic_secure_login_is_otp_enabled() {
    return (bool) oyic_secure_login_get_option('enable_otp_login', false);
}

/**
 * Log security event
 * 
 * Logs security-related events for monitoring and debugging.
 * 
 * @since 1.0.0
 * @param string $event Event type
 * @param string $message Event message
 * @param array $context Additional context data
 * @return void
 */
function oyic_secure_login_log_event($event, $message, $context = array()) {
    $log_data = array(
        'timestamp' => current_time('mysql'),
        'event' => $event,
        'message' => $message,
        'context' => $context,
        'ip' => oyic_secure_login_get_client_ip(),
        'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
    );
    
    /**
     * Filter security log data before logging
     * 
     * @since 1.0.0
     * @param array $log_data Log data
     * @param string $event Event type
     */
    $log_data = apply_filters('oyic_secure_login_log_data', $log_data, $event);
    
    // Log to WordPress debug log if enabled
    if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
        error_log('OYIC Secure Login [' . $event . ']: ' . $message . ' ' . wp_json_encode($context));
    }
    
    /**
     * Fires after security event is logged
     * 
     * @since 1.0.0
     * @param array $log_data Log data
     * @param string $event Event type
     */
    do_action('oyic_secure_login_event_logged', $log_data, $event);
}

/**
 * Get client IP address
 * 
 * Attempts to get the real client IP address, accounting for proxies.
 * 
 * @since 1.0.0
 * @return string Client IP address
 */
function oyic_secure_login_get_client_ip() {
    $ip_keys = array(
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    );
    
    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            $ip_list = explode(',', $_SERVER[$key]);
            $ip = trim($ip_list[0]);
            
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    // Fallback to REMOTE_ADDR
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

/**
 * Generate secure random string
 * 
 * Generates a cryptographically secure random string.
 * 
 * @since 1.0.0
 * @param int $length String length
 * @param string $characters Character set to use
 * @return string Random string
 */
function oyic_secure_login_generate_random_string($length = 32, $characters = null) {
    if ($characters === null) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }
    
    $string = '';
    $max = strlen($characters) - 1;
    
    for ($i = 0; $i < $length; $i++) {
        $string .= $characters[wp_rand(0, $max)];
    }
    
    return $string;
}

/**
 * Sanitize login slug
 * 
 * Sanitizes and validates a login slug.
 * 
 * @since 1.0.0
 * @param string $slug Login slug to sanitize
 * @return string Sanitized slug
 */
function oyic_secure_login_sanitize_slug($slug) {
    // Remove special characters and convert to lowercase
    $slug = strtolower(trim($slug));
    $slug = preg_replace('/[^a-z0-9\-_]/', '', $slug);
    
    // Remove consecutive dashes/underscores
    $slug = preg_replace('/[\-_]+/', '-', $slug);
    
    // Trim dashes from beginning and end
    $slug = trim($slug, '-_');
    
    // Ensure minimum length
    if (strlen($slug) < 3) {
        $slug = 'secure-access';
    }
    
    // Check against reserved words
    $reserved = array(
        'admin', 'administrator', 'login', 'wp-admin', 'wp-login',
        'dashboard', 'panel', 'control', 'manage', 'backend'
    );
    
    if (in_array($slug, $reserved, true)) {
        $slug .= '-login';
    }
    
    /**
     * Filter sanitized login slug
     * 
     * @since 1.0.0
     * @param string $slug Sanitized slug
     * @param string $original_slug Original slug
     */
    return apply_filters('oyic_secure_login_sanitize_slug', $slug, $slug);
}

/**
 * Check if current request is for custom login page
 * 
 * @since 1.0.0
 * @return bool True if custom login page, false otherwise
 */
function oyic_secure_login_is_custom_login_page() {
    return get_query_var('oyic_secure_login') === '1';
}

/**
 * Get formatted time difference
 * 
 * Returns a human-readable time difference string.
 * 
 * @since 1.0.0
 * @param int $timestamp Unix timestamp
 * @return string Formatted time difference
 */
function oyic_secure_login_time_diff($timestamp) {
    $now = current_time('timestamp');
    $diff = $now - $timestamp;
    
    if ($diff < 60) {
        /* translators: %d: Number of seconds */
        return sprintf(_n('%d second ago', '%d seconds ago', $diff, 'oyic-secure-login'), $diff);
    } elseif ($diff < 3600) {
        $minutes = floor($diff / 60);
        /* translators: %d: Number of minutes */
        return sprintf(_n('%d minute ago', '%d minutes ago', $minutes, 'oyic-secure-login'), $minutes);
    } elseif ($diff < 86400) {
        $hours = floor($diff / 3600);
        /* translators: %d: Number of hours */
        return sprintf(_n('%d hour ago', '%d hours ago', $hours, 'oyic-secure-login'), $hours);
    } else {
        $days = floor($diff / 86400);
        /* translators: %d: Number of days */
        return sprintf(_n('%d day ago', '%d days ago', $days, 'oyic-secure-login'), $days);
    }
}

/**
 * Validate email address
 * 
 * Validates an email address with additional security checks.
 * 
 * @since 1.0.0
 * @param string $email Email address to validate
 * @return bool True if valid, false otherwise
 */
function oyic_secure_login_validate_email($email) {
    // Basic validation
    if (!is_email($email)) {
        return false;
    }
    
    // Check for disposable email domains
    $disposable_domains = apply_filters('oyic_secure_login_disposable_domains', array(
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com'
    ));
    
    $domain = substr(strrchr($email, '@'), 1);
    if (in_array($domain, $disposable_domains, true)) {
        return false;
    }
    
    return true;
}

/**
 * Format OTP code for display
 * 
 * Formats an OTP code with proper spacing for better readability.
 * 
 * @since 1.0.0
 * @param string $code OTP code
 * @return string Formatted code
 */
function oyic_secure_login_format_otp_code($code) {
    // Add space every 3 digits for 6-digit codes
    if (strlen($code) === 6) {
        return substr($code, 0, 3) . ' ' . substr($code, 3);
    }
    
    return $code;
}
