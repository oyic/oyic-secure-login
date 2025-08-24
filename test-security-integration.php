<?php
/**
 * Test Security Integration
 * 
 * Simple test file to verify that the security enhancements are working.
 * This file should be removed in production.
 * 
 * @package OYIC\SecureLogin
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Test Security Features
 * 
 * @since 1.0.0
 */
function oyic_test_security_features() {
    if (!current_user_can('manage_options')) {
        return;
    }

    echo '<div class="notice notice-info">';
    echo '<h3>OYIC Secure Login - Security Features Test</h3>';
    
    // Test DISALLOW_FILE_EDIT
    echo '<p><strong>DISALLOW_FILE_EDIT:</strong> ';
    if (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) {
        echo '<span style="color: green;">✓ Enabled</span>';
    } else {
        echo '<span style="color: red;">✗ Disabled</span>';
    }
    echo '</p>';
    
    // Test XML-RPC
    echo '<p><strong>XML-RPC:</strong> ';
    if (apply_filters('xmlrpc_enabled', true) === false) {
        echo '<span style="color: green;">✓ Disabled</span>';
    } else {
        echo '<span style="color: red;">✗ Enabled</span>';
    }
    echo '</p>';
    
    // Test WordPress version hiding
    echo '<p><strong>WordPress Version Hiding:</strong> ';
    global $wp_filter;
    if (isset($wp_filter['wp_head']) && !has_action('wp_head', 'wp_generator')) {
        echo '<span style="color: green;">✓ Enabled</span>';
    } else {
        echo '<span style="color: red;">✗ Disabled</span>';
    }
    echo '</p>';
    
    // Test rate limiting
    echo '<p><strong>Rate Limiting:</strong> ';
    $rate_limit_status = oyic_secure_login_get_rate_limit_status();
    echo '<span style="color: blue;">Current attempts: ' . $rate_limit_status['attempts'] . '/5</span>';
    echo '</p>';
    
    // Test user enumeration prevention
    echo '<p><strong>User Enumeration Prevention:</strong> ';
    if (has_action('init', array('OYIC_Security_Enhancements', 'prevent_user_enumeration'))) {
        echo '<span style="color: green;">✓ Enabled</span>';
    } else {
        echo '<span style="color: red;">✗ Disabled</span>';
    }
    echo '</p>';
    
    // Test override key functionality
    echo '<p><strong>Override Key:</strong> ';
    $override_key = oyic_secure_login_get_option('override_key');
    if (!empty($override_key)) {
        echo '<span style="color: green;">✓ Set (' . substr($override_key, 0, 8) . '...)</span>';
        echo '<br><small>Emergency URL: <code>' . oyic_secure_login_get_override_url() . '</code></small>';
    } else {
        echo '<span style="color: red;">✗ Not set</span>';
    }
    echo '</p>';
    
    echo '</div>';
}

// Add test to admin notices
add_action('admin_notices', 'oyic_test_security_features');
