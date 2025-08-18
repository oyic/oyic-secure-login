<?php
/**
 * PHPUnit Bootstrap File for OYIC Secure Login
 * 
 * Sets up the testing environment for the plugin.
 * 
 * @package OYIC\SecureLogin\Tests
 * @since 1.0.0
 */

// Define test environment constants
define('OYIC_SECURE_LOGIN_TESTING', true);

// Get the WordPress tests directory
$_tests_dir = getenv('WP_TESTS_DIR');

if (!$_tests_dir) {
    $_tests_dir = rtrim(sys_get_temp_dir(), '/\\') . '/wordpress-tests-lib';
}

// Give access to tests_add_filter() function
require_once $_tests_dir . '/includes/functions.php';

/**
 * Manually load the plugin being tested
 */
function _manually_load_plugin() {
    require dirname(dirname(__FILE__)) . '/oyic-secure-login.php';
}

tests_add_filter('muplugins_loaded', '_manually_load_plugin');

// Start up the WP testing environment
require $_tests_dir . '/includes/bootstrap.php';

// Load plugin test helpers
require_once dirname(__FILE__) . '/includes/class-test-case.php';
require_once dirname(__FILE__) . '/includes/class-test-helpers.php';
