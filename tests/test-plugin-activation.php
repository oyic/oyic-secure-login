<?php
/**
 * Test Plugin Activation and Basic Functionality
 * 
 * @package OYIC\SecureLogin\Tests
 * @since 1.0.0
 */

use OYIC\SecureLogin\Tests\TestCase;

/**
 * Plugin activation tests
 */
class PluginActivationTest extends TestCase {

    /**
     * Test plugin activation
     */
    public function test_plugin_activation() {
        // Test that plugin is loaded
        $this->assertTrue(function_exists('oyic_secure_login'), 'Plugin main function should exist');
        
        // Test that main class exists
        $this->assertTrue(class_exists('OYIC_Secure_Login'), 'Main plugin class should exist');
        
        // Test that plugin instance is created
        $plugin = oyic_secure_login();
        $this->assertInstanceOf('OYIC_Secure_Login', $plugin, 'Plugin instance should be created');
    }

    /**
     * Test plugin constants
     */
    public function test_plugin_constants() {
        $constants = array(
            'OYIC_SECURE_LOGIN_VERSION',
            'OYIC_SECURE_LOGIN_PLUGIN_FILE',
            'OYIC_SECURE_LOGIN_PLUGIN_DIR',
            'OYIC_SECURE_LOGIN_PLUGIN_URL',
            'OYIC_SECURE_LOGIN_PLUGIN_BASENAME',
        );

        foreach ($constants as $constant) {
            $this->assertTrue(defined($constant), "Constant {$constant} should be defined");
        }
    }

    /**
     * Test database table creation
     */
    public function test_database_table_creation() {
        // Trigger activation
        $plugin = oyic_secure_login();
        $plugin->activate();
        
        // Check that OTP table exists
        $this->assertTableExists('otp');
    }

    /**
     * Test default options creation
     */
    public function test_default_options_creation() {
        // Trigger activation
        $plugin = oyic_secure_login();
        $plugin->activate();
        
        // Check that options are created
        $options = get_option('oyic_secure_login_options');
        $this->assertIsArray($options, 'Plugin options should be an array');
        
        // Check default values
        $this->assertFalse($options['enable_custom_login'], 'Custom login should be disabled by default');
        $this->assertEquals('secure-access', $options['custom_login_slug'], 'Default slug should be set');
        $this->assertFalse($options['enable_otp_login'], 'OTP login should be disabled by default');
        $this->assertNotEmpty($options['override_key'], 'Override key should be generated');
    }

    /**
     * Test component initialization
     */
    public function test_component_initialization() {
        $plugin = oyic_secure_login();
        
        // Test that components are initialized
        $this->assertNotNull($plugin->get_component('database'), 'Database component should be initialized');
        $this->assertNotNull($plugin->get_component('security'), 'Security component should be initialized');
        $this->assertNotNull($plugin->get_component('auth'), 'Auth component should be initialized');
    }

    /**
     * Test admin component initialization
     */
    public function test_admin_component_initialization() {
        // Mock admin environment
        set_current_screen('dashboard');
        
        $plugin = oyic_secure_login();
        $plugin->init_admin();
        
        $this->assertNotNull($plugin->get_component('admin'), 'Admin component should be initialized');
    }

    /**
     * Test helper functions
     */
    public function test_helper_functions() {
        $functions = array(
            'oyic_secure_login_get_option',
            'oyic_secure_login_update_option',
            'oyic_secure_login_get_login_url',
            'oyic_secure_login_get_override_url',
            'oyic_secure_login_is_custom_login_enabled',
            'oyic_secure_login_is_otp_enabled',
            'oyic_secure_login_log_event',
            'oyic_secure_login_get_client_ip',
        );

        foreach ($functions as $function) {
            $this->assertTrue(function_exists($function), "Function {$function} should exist");
        }
    }

    /**
     * Test plugin deactivation
     */
    public function test_plugin_deactivation() {
        $plugin = oyic_secure_login();
        
        // Activate first
        $plugin->activate();
        
        // Deactivate
        $plugin->deactivate();
        
        // Check that transients are cleaned up
        $this->assertTransientNotExists('oyic_secure_login_flush_rules');
    }

    /**
     * Test WordPress version compatibility
     */
    public function test_wordpress_version_compatibility() {
        global $wp_version;
        
        $this->assertTrue(
            version_compare($wp_version, '5.0', '>='),
            'WordPress version should be 5.0 or higher'
        );
    }

    /**
     * Test PHP version compatibility
     */
    public function test_php_version_compatibility() {
        $this->assertTrue(
            version_compare(PHP_VERSION, '7.4', '>='),
            'PHP version should be 7.4 or higher'
        );
    }

    /**
     * Test required WordPress functions
     */
    public function test_required_wordpress_functions() {
        $required_functions = array(
            'add_action',
            'add_filter',
            'wp_enqueue_script',
            'wp_enqueue_style',
            'wp_create_nonce',
            'wp_verify_nonce',
            'sanitize_text_field',
            'sanitize_email',
            'wp_mail',
        );

        foreach ($required_functions as $function) {
            $this->assertTrue(function_exists($function), "Required function {$function} should exist");
        }
    }

    /**
     * Test plugin text domain loading
     */
    public function test_text_domain_loading() {
        $plugin = oyic_secure_login();
        $plugin->load_textdomain();
        
        // Test that text domain is loaded
        $this->assertTrue(is_textdomain_loaded('oyic-secure-login'), 'Text domain should be loaded');
    }

    /**
     * Test plugin options getter and setter
     */
    public function test_plugin_options() {
        $plugin = oyic_secure_login();
        
        // Test getting all options
        $options = $plugin->get_options();
        $this->assertIsArray($options, 'Options should be an array');
        
        // Test getting specific option
        $slug = $plugin->get_options('custom_login_slug');
        $this->assertEquals('secure-access', $slug, 'Default slug should be returned');
        
        // Test updating option
        $result = $plugin->update_option('custom_login_slug', 'new-slug');
        $this->assertTrue($result, 'Option update should succeed');
        
        // Test that option was updated
        $updated_slug = $plugin->get_options('custom_login_slug');
        $this->assertEquals('new-slug', $updated_slug, 'Option should be updated');
    }
}
