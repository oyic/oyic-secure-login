<?php
/**
 * PSR-4 Autoloader for OYIC Secure Login
 * 
 * This file implements PSR-4 autoloading for the plugin classes.
 * It maps the OYIC\SecureLogin namespace to the src/ directory.
 * 
 * @package OYIC\SecureLogin
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * PSR-4 Autoloader
 * 
 * Automatically loads classes based on their namespace and class name.
 * Follows PSR-4 standard for autoloading.
 * 
 * @since 1.0.0
 * @param string $class_name The fully qualified class name
 * @return void
 */
spl_autoload_register(function ($class_name) {
    // Base namespace for this plugin
    $namespace_prefix = 'OYIC\\SecureLogin\\';
    
    // Base directory for the namespace prefix
    $base_dir = OYIC_SECURE_LOGIN_PLUGIN_DIR . 'src/';
    
    // Check if the class uses the namespace prefix
    $len = strlen($namespace_prefix);
    if (strncmp($namespace_prefix, $class_name, $len) !== 0) {
        // No, move to the next registered autoloader
        return;
    }
    
    // Get the relative class name
    $relative_class = substr($class_name, $len);
    
    // Replace the namespace prefix with the base directory, replace namespace
    // separators with directory separators in the relative class name, append
    // with .php
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    
    // If the file exists, require it
    if (file_exists($file)) {
        require_once $file;
    }
});

/**
 * Load compatibility functions
 * 
 * These functions provide backward compatibility and helper functions
 * that may be needed throughout the plugin.
 * 
 * @since 1.0.0
 */
if (file_exists(OYIC_SECURE_LOGIN_PLUGIN_DIR . 'includes/compatibility.php')) {
    require_once OYIC_SECURE_LOGIN_PLUGIN_DIR . 'includes/compatibility.php';
}

/**
 * Load helper functions
 * 
 * These are global helper functions that can be used throughout
 * the plugin and by third-party developers.
 * 
 * @since 1.0.0
 */
if (file_exists(OYIC_SECURE_LOGIN_PLUGIN_DIR . 'includes/functions.php')) {
    require_once OYIC_SECURE_LOGIN_PLUGIN_DIR . 'includes/functions.php';
}

/**
 * Load security enhancements
 * 
 * Additional security features that complement the main plugin functionality.
 * 
 * @since 1.0.0
 */
if (file_exists(OYIC_SECURE_LOGIN_PLUGIN_DIR . 'includes/security-enhancements.php')) {
    require_once OYIC_SECURE_LOGIN_PLUGIN_DIR . 'includes/security-enhancements.php';
}
