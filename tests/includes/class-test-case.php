<?php
/**
 * Base Test Case for OYIC Secure Login Tests
 * 
 * @package OYIC\SecureLogin\Tests
 * @since 1.0.0
 */

namespace OYIC\SecureLogin\Tests;

/**
 * Base test case class
 */
class TestCase extends \WP_UnitTestCase {

    /**
     * Plugin instance
     * 
     * @var \OYIC_Secure_Login
     */
    protected $plugin;

    /**
     * Test user ID
     * 
     * @var int
     */
    protected $test_user_id;

    /**
     * Setup before each test
     */
    public function setUp(): void {
        parent::setUp();
        
        // Get plugin instance
        $this->plugin = oyic_secure_login();
        
        // Create test user
        $this->test_user_id = $this->factory->user->create(array(
            'user_login' => 'testuser',
            'user_email' => 'test@example.com',
            'user_pass' => 'testpass123',
            'role' => 'subscriber'
        ));
        
        // Reset plugin options to defaults
        $this->reset_plugin_options();
        
        // Clear any existing transients
        $this->clear_plugin_transients();
    }

    /**
     * Cleanup after each test
     */
    public function tearDown(): void {
        // Clean up test data
        wp_delete_user($this->test_user_id);
        
        // Reset plugin state
        $this->reset_plugin_options();
        $this->clear_plugin_transients();
        
        parent::tearDown();
    }

    /**
     * Reset plugin options to defaults
     */
    protected function reset_plugin_options() {
        $defaults = array(
            'enable_custom_login' => false,
            'custom_login_slug' => 'secure-access',
            'enable_otp_login' => false,
            'override_key' => 'test-override-key',
            'otp_expiry_minutes' => 10,
            'rate_limit_attempts' => 3,
            'rate_limit_window' => 5,
            'email_from_name' => 'Test Site',
            'email_from_address' => 'test@example.com',
        );
        
        update_option('oyic_secure_login_options', $defaults);
    }

    /**
     * Clear plugin transients
     */
    protected function clear_plugin_transients() {
        global $wpdb;
        
        $wpdb->query(
            "DELETE FROM {$wpdb->options} 
             WHERE option_name LIKE '_transient_oyic_%' 
             OR option_name LIKE '_transient_timeout_oyic_%'"
        );
    }

    /**
     * Create test OTP record
     * 
     * @param string $email Email address
     * @param string $code OTP code (will be hashed)
     * @return int|false Insert ID or false on failure
     */
    protected function create_test_otp($email, $code = '123456') {
        $database = $this->plugin->get_component('database');
        
        if (!$database) {
            return false;
        }
        
        $hashed_code = wp_hash_password($code);
        return $database->store_otp($email, $hashed_code, 10);
    }

    /**
     * Simulate AJAX request
     * 
     * @param string $action AJAX action
     * @param array $data Request data
     * @param bool $logged_in Whether user should be logged in
     * @return array Response data
     */
    protected function simulate_ajax_request($action, $data = array(), $logged_in = false) {
        if ($logged_in) {
            wp_set_current_user($this->test_user_id);
        }
        
        $_POST = array_merge($_POST, $data);
        $_REQUEST = array_merge($_REQUEST, $data);
        
        try {
            $this->_handleAjax($action);
        } catch (\WPAjaxDieContinueException $e) {
            unset($e);
        }
        
        $response = json_decode($this->_last_response, true);
        
        // Clean up
        $_POST = array();
        $_REQUEST = array();
        wp_set_current_user(0);
        
        return $response;
    }

    /**
     * Assert that an option exists and has expected value
     * 
     * @param string $option_name Option name
     * @param mixed $expected_value Expected value
     */
    protected function assertOptionEquals($option_name, $expected_value) {
        $actual_value = get_option($option_name);
        $this->assertEquals($expected_value, $actual_value, "Option {$option_name} does not match expected value");
    }

    /**
     * Assert that a transient exists
     * 
     * @param string $transient_name Transient name
     */
    protected function assertTransientExists($transient_name) {
        $value = get_transient($transient_name);
        $this->assertNotFalse($value, "Transient {$transient_name} does not exist");
    }

    /**
     * Assert that a transient does not exist
     * 
     * @param string $transient_name Transient name
     */
    protected function assertTransientNotExists($transient_name) {
        $value = get_transient($transient_name);
        $this->assertFalse($value, "Transient {$transient_name} should not exist");
    }

    /**
     * Assert that user can login with credentials
     * 
     * @param string $username Username
     * @param string $password Password
     */
    protected function assertUserCanLogin($username, $password) {
        $user = wp_authenticate($username, $password);
        $this->assertInstanceOf('\WP_User', $user, 'User should be able to login');
        $this->assertFalse(is_wp_error($user), 'Login should not return error');
    }

    /**
     * Assert that user cannot login with credentials
     * 
     * @param string $username Username
     * @param string $password Password
     */
    protected function assertUserCannotLogin($username, $password) {
        $user = wp_authenticate($username, $password);
        $this->assertInstanceOf('\WP_Error', $user, 'Login should return error');
    }

    /**
     * Mock $_SERVER variables
     * 
     * @param array $server_vars Server variables to set
     */
    protected function mock_server_vars($server_vars) {
        foreach ($server_vars as $key => $value) {
            $_SERVER[$key] = $value;
        }
    }

    /**
     * Get test email content
     * 
     * @return string Test email content
     */
    protected function get_test_email_content() {
        return 'This is a test email from OYIC Secure Login.';
    }

    /**
     * Assert that email was sent
     */
    protected function assertEmailSent() {
        global $phpmailer;
        
        if (!isset($phpmailer) || !is_object($phpmailer)) {
            $this->fail('PHPMailer object not found');
        }
        
        $this->assertGreaterThan(0, $phpmailer->get_sent_count(), 'No emails were sent');
    }

    /**
     * Assert that no email was sent
     */
    protected function assertEmailNotSent() {
        global $phpmailer;
        
        if (!isset($phpmailer) || !is_object($phpmailer)) {
            return; // No mailer means no emails sent
        }
        
        $this->assertEquals(0, $phpmailer->get_sent_count(), 'Emails were sent when none expected');
    }

    /**
     * Get database table name
     * 
     * @param string $table_suffix Table suffix
     * @return string Full table name
     */
    protected function get_table_name($table_suffix) {
        global $wpdb;
        return $wpdb->prefix . 'oyic_secure_login_' . $table_suffix;
    }

    /**
     * Assert that database table exists
     * 
     * @param string $table_suffix Table suffix
     */
    protected function assertTableExists($table_suffix) {
        global $wpdb;
        
        $table_name = $this->get_table_name($table_suffix);
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") === $table_name;
        
        $this->assertTrue($table_exists, "Table {$table_name} should exist");
    }

    /**
     * Assert that database table does not exist
     * 
     * @param string $table_suffix Table suffix
     */
    protected function assertTableNotExists($table_suffix) {
        global $wpdb;
        
        $table_name = $this->get_table_name($table_suffix);
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") === $table_name;
        
        $this->assertFalse($table_exists, "Table {$table_name} should not exist");
    }
}
