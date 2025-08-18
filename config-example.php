<?php
/**
 * Configuration Examples for Secure Login Plugin
 * 
 * These examples show how to customize the plugin behavior using WordPress hooks
 * Add these to your theme's functions.php or a custom plugin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Customize OTP email subject
 */
add_filter('secure_login_otp_email_subject', function($subject, $email) {
    return 'Your secure login code for ' . get_bloginfo('name');
}, 10, 2);

/**
 * Customize OTP email message (HTML version)
 */
add_filter('secure_login_otp_email_message', function($message, $otp_code, $email) {
    $site_name = get_bloginfo('name');
    $site_url = home_url();
    
    return "
    <html>
    <body style='font-family: Arial, sans-serif; color: #333;'>
        <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
            <h2 style='color: #667eea;'>Login Code for {$site_name}</h2>
            
            <p>Hello,</p>
            
            <p>You requested a login code for your account. Your secure login code is:</p>
            
            <div style='background: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;'>
                <span style='font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #667eea;'>{$otp_code}</span>
            </div>
            
            <p><strong>Important:</strong></p>
            <ul>
                <li>This code will expire in 10 minutes</li>
                <li>Use this code only on {$site_url}</li>
                <li>Never share this code with anyone</li>
            </ul>
            
            <p>If you didn't request this login code, please ignore this email and consider changing your account password.</p>
            
            <hr style='margin: 30px 0; border: none; border-top: 1px solid #eee;'>
            <p style='font-size: 12px; color: #666;'>
                This email was sent from {$site_name} ({$site_url})
            </p>
        </div>
    </body>
    </html>
    ";
}, 10, 3);

/**
 * Set email headers for HTML content
 */
add_filter('secure_login_otp_email_headers', function($headers) {
    $headers[] = 'Content-Type: text/html; charset=UTF-8';
    return $headers;
});

/**
 * Extend OTP expiry time to 30 minutes
 */
add_filter('secure_login_otp_expiry_time', function($seconds) {
    return 1800; // 30 minutes instead of default 10 minutes
});

/**
 * Reduce rate limiting to 2 attempts per 5 minutes
 */
add_filter('secure_login_rate_limit_attempts', function($attempts) {
    return 2; // Default is 3
});

/**
 * Change rate limiting time window to 10 minutes
 */
add_filter('secure_login_rate_limit_window', function($minutes) {
    return 10; // Default is 5 minutes
});

/**
 * Custom login redirect for specific user roles
 */
add_action('secure_login_after_standard_login', function($user) {
    if (in_array('subscriber', $user->roles)) {
        wp_redirect(home_url('/dashboard/'));
        exit;
    }
}, 10, 1);

/**
 * Log OTP login attempts for security monitoring
 */
add_action('secure_login_before_otp_send', function($email) {
    error_log("OTP requested for email: {$email} from IP: " . $_SERVER['REMOTE_ADDR']);
});

add_action('secure_login_after_otp_verify', function($user, $success) {
    $status = $success ? 'SUCCESS' : 'FAILED';
    error_log("OTP verification {$status} for user: {$user->user_email} from IP: " . $_SERVER['REMOTE_ADDR']);
}, 10, 2);

/**
 * Disable OTP login for admin users (force password login)
 */
add_filter('secure_login_allow_otp_for_user', function($allowed, $user) {
    if (user_can($user, 'manage_options')) {
        return false; // Admins must use password
    }
    return $allowed;
}, 10, 2);

/**
 * Custom validation for login slugs
 */
add_filter('secure_login_validate_slug', function($is_valid, $slug) {
    // Disallow certain reserved words
    $reserved = ['admin', 'login', 'wp-admin', 'wp-login', 'administrator'];
    
    if (in_array(strtolower($slug), $reserved)) {
        return false;
    }
    
    // Must be at least 8 characters
    if (strlen($slug) < 8) {
        return false;
    }
    
    return $is_valid;
}, 10, 2);

/**
 * Add custom CSS to login page
 */
add_action('secure_login_head', function() {
    echo '<style>
        #loginform-container {
            background: linear-gradient(135deg, #your-color1 0%, #your-color2 100%) !important;
        }
        .login-header h1 a {
            color: #your-brand-color !important;
        }
    </style>';
});

/**
 * Add custom JavaScript to login page
 */
add_action('secure_login_footer', function() {
    echo '<script>
        // Custom JavaScript for your login page
        console.log("Custom secure login page loaded");
    </script>';
});

/**
 * Integration with other security plugins
 * Example: Wordfence integration
 */
add_action('secure_login_failed_attempt', function($username, $ip) {
    // Log failed attempt with Wordfence if available
    if (class_exists('wfUtils')) {
        wfUtils::wordfenceLog("Secure Login failed attempt: {$username} from {$ip}");
    }
});

/**
 * Custom brute force protection
 */
add_filter('secure_login_max_attempts', function($max_attempts, $ip) {
    // Allow more attempts for trusted IPs
    $trusted_ips = ['192.168.1.100', '10.0.0.50'];
    
    if (in_array($ip, $trusted_ips)) {
        return $max_attempts * 2;
    }
    
    return $max_attempts;
}, 10, 2);

/**
 * Notification when someone accesses override URL
 */
add_action('secure_login_override_access', function($ip, $user_agent) {
    $subject = 'Emergency override access used - ' . get_bloginfo('name');
    $message = "Someone accessed your WordPress admin using the emergency override URL.\n\n";
    $message .= "IP Address: {$ip}\n";
    $message .= "User Agent: {$user_agent}\n";
    $message .= "Time: " . current_time('mysql') . "\n\n";
    $message .= "If this wasn't you, please check your site security immediately.";
    
    wp_mail(get_option('admin_email'), $subject, $message);
});

/**
 * Custom database table prefix for OTP storage
 */
add_filter('secure_login_otp_table_name', function($table_name) {
    global $wpdb;
    return $wpdb->prefix . 'my_custom_otp_table';
});

/**
 * Integration with membership plugins
 * Example: Restrict OTP login to active members only
 */
add_filter('secure_login_allow_otp_login', function($allowed, $email) {
    // Check if user has active membership
    $user = get_user_by('email', $email);
    
    if ($user && function_exists('pmpro_hasMembershipLevel')) {
        return pmpro_hasMembershipLevel(null, $user->ID);
    }
    
    return $allowed;
}, 10, 2);
