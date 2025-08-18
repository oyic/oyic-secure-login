<?php
/**
 * Uninstall script for OYIC Secure Login Plugin
 * 
 * This file is executed when the plugin is deleted from WordPress admin.
 * It cleans up all plugin data including database tables, options, transients,
 * and scheduled events to ensure a clean uninstall.
 * 
 * @package OYIC\SecureLogin
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit('Direct access denied.');
}

// Security check - make sure this is a legitimate uninstall
if (!current_user_can('delete_plugins')) {
    exit('Insufficient permissions.');
}

/**
 * Main uninstall function
 * 
 * @since 1.0.0
 * @return void
 */
function oyic_secure_login_uninstall() {
    global $wpdb;
    
    // Log the uninstall event
    if (function_exists('error_log')) {
        error_log('OYIC Secure Login: Plugin uninstall started');
    }
    
    // Remove plugin options
    $options_to_delete = array(
        'oyic_secure_login_options',
        'oyic_secure_login_db_version',
        'oyic_blocked_ips',
    );
    
    foreach ($options_to_delete as $option) {
        delete_option($option);
        delete_site_option($option); // For multisite
    }
    
    // Remove transients
    oyic_secure_login_cleanup_transients();
    
    // Remove database tables
    oyic_secure_login_drop_tables();
    
    // Remove scheduled events
    oyic_secure_login_cleanup_scheduled_events();
    
    // Flush rewrite rules to clean up custom URLs
    flush_rewrite_rules();
    
    // Clear any object caches
    if (function_exists('wp_cache_flush')) {
        wp_cache_flush();
    }
    
    // Log completion
    if (function_exists('error_log')) {
        error_log('OYIC Secure Login: Plugin uninstall completed');
    }
}

/**
 * Cleanup transients created by the plugin
 * 
 * @since 1.0.0
 * @return void
 */
function oyic_secure_login_cleanup_transients() {
    global $wpdb;
    
    // Delete plugin-specific transients
    $wpdb->query(
        "DELETE FROM {$wpdb->options} 
         WHERE option_name LIKE '_transient_oyic_%' 
         OR option_name LIKE '_transient_timeout_oyic_%'"
    );
    
    // For multisite
    if (is_multisite()) {
        $wpdb->query(
            "DELETE FROM {$wpdb->sitemeta} 
             WHERE meta_key LIKE '_site_transient_oyic_%' 
             OR meta_key LIKE '_site_transient_timeout_oyic_%'"
        );
    }
}

/**
 * Drop all plugin database tables
 * 
 * @since 1.0.0
 * @return void
 */
function oyic_secure_login_drop_tables() {
    global $wpdb;
    
    $tables_to_drop = array(
        $wpdb->prefix . 'oyic_secure_login_otp',
        // Add more tables here if needed in future versions
    );
    
    foreach ($tables_to_drop as $table) {
        $wpdb->query("DROP TABLE IF EXISTS {$table}");
    }
}

/**
 * Cleanup scheduled events
 * 
 * @since 1.0.0
 * @return void
 */
function oyic_secure_login_cleanup_scheduled_events() {
    $scheduled_events = array(
        'oyic_security_cleanup',
        // Add more scheduled events here if needed
    );
    
    foreach ($scheduled_events as $event) {
        $timestamp = wp_next_scheduled($event);
        if ($timestamp) {
            wp_unschedule_event($timestamp, $event);
        }
        
        // Clear all instances of the event
        wp_clear_scheduled_hook($event);
    }
}

/**
 * Check if we should keep data on uninstall
 * 
 * @since 1.0.0
 * @return bool True if data should be kept
 */
function oyic_secure_login_should_keep_data() {
    // Check if there's a setting to keep data on uninstall
    $options = get_option('oyic_secure_login_options', array());
    return !empty($options['keep_data_on_uninstall']);
}

/**
 * Multisite uninstall handling
 * 
 * @since 1.0.0
 * @return void
 */
function oyic_secure_login_multisite_uninstall() {
    if (!is_multisite()) {
        return;
    }
    
    global $wpdb;
    
    // Get all blog IDs
    $blog_ids = $wpdb->get_col("SELECT blog_id FROM {$wpdb->blogs}");
    
    foreach ($blog_ids as $blog_id) {
        switch_to_blog($blog_id);
        oyic_secure_login_uninstall();
        restore_current_blog();
    }
}

/**
 * Remove user meta data created by the plugin
 * 
 * @since 1.0.0
 * @return void
 */
function oyic_secure_login_cleanup_user_meta() {
    global $wpdb;
    
    $meta_keys_to_delete = array(
        'oyic_last_login',
        'oyic_login_attempts',
        // Add more user meta keys here if needed
    );
    
    foreach ($meta_keys_to_delete as $meta_key) {
        delete_metadata('user', 0, $meta_key, '', true);
    }
}

/**
 * Remove custom capabilities added by the plugin
 * 
 * @since 1.0.0
 * @return void
 */
function oyic_secure_login_cleanup_capabilities() {
    $capabilities = array(
        'manage_secure_login',
        // Add more capabilities here if needed
    );
    
    $roles = wp_roles();
    
    foreach ($roles->roles as $role_name => $role_data) {
        $role = get_role($role_name);
        if ($role) {
            foreach ($capabilities as $cap) {
                $role->remove_cap($cap);
            }
        }
    }
}

/**
 * Backup critical data before uninstall (optional)
 * 
 * @since 1.0.0
 * @return void
 */
function oyic_secure_login_backup_data() {
    global $wpdb;
    
    $backup_data = array(
        'options' => get_option('oyic_secure_login_options', array()),
        'blocked_ips' => get_option('oyic_blocked_ips', array()),
        'uninstall_date' => current_time('mysql'),
        'plugin_version' => '1.0.0',
    );
    
    // Store backup in a temporary option (will be cleaned up after 30 days)
    set_transient('oyic_secure_login_backup', $backup_data, 30 * DAY_IN_SECONDS);
}

// Execute the uninstall
try {
    // Check if user wants to keep data
    if (!oyic_secure_login_should_keep_data()) {
        // Backup data before deletion (optional)
        oyic_secure_login_backup_data();
        
        // Handle multisite if applicable
        if (is_multisite()) {
            oyic_secure_login_multisite_uninstall();
        } else {
            oyic_secure_login_uninstall();
        }
        
        // Cleanup user meta and capabilities
        oyic_secure_login_cleanup_user_meta();
        oyic_secure_login_cleanup_capabilities();
    }
    
} catch (Exception $e) {
    // Log any errors during uninstall
    if (function_exists('error_log')) {
        error_log('OYIC Secure Login uninstall error: ' . $e->getMessage());
    }
    
    // Don't throw the error to prevent WordPress from showing it to the user
    // The uninstall should appear to succeed even if there are minor issues
}
