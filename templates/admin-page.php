<?php
/**
 * Admin Page Template for OYIC Secure Login
 * 
 * @package OYIC\SecureLogin
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

// Get plugin instance and options
$plugin = oyic_secure_login();
$options = $plugin->get_options();

$custom_login_url = oyic_secure_login_get_login_url();
$override_url = oyic_secure_login_get_override_url();
?>

<div class="wrap">
    <h1><?php echo esc_html__('OYIC Secure Login Settings', 'oyic-secure-login'); ?></h1>
    
    <?php settings_errors(); ?>
    
    <div class="card" style="max-width: none; margin-top: 20px;">
        <h2><?php echo esc_html__('Quick Access URLs', 'oyic-secure-login'); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php echo esc_html__('Custom Login URL', 'oyic-secure-login'); ?></th>
                <td>
                    <a href="<?php echo esc_url($custom_login_url); ?>" target="_blank">
                        <?php echo esc_html($custom_login_url); ?>
                    </a>
                    <p class="description"><?php echo esc_html__('This is your custom login page URL', 'oyic-secure-login'); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php echo esc_html__('Override URL', 'oyic-secure-login'); ?></th>
                <td>
                    <code><?php echo esc_html($override_url); ?></code>
                    <p class="description"><?php echo esc_html__('Use this URL to access the original wp-login.php when custom login is enabled', 'oyic-secure-login'); ?></p>
                </td>
            </tr>
        </table>
    </div>
    
    <form method="post" action="options.php">
        <?php
        settings_fields('oyic_secure_login_settings');
        do_settings_sections('oyic-secure-login');
        ?>
        
        <?php submit_button(); ?>
    </form>
    
    <div class="card" style="max-width: none; margin-top: 20px;">
        <h2><?php echo esc_html__('System Status', 'oyic-secure-login'); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php echo esc_html__('Database Table', 'oyic-secure-login'); ?></th>
                <td>
                    <?php 
                    global $wpdb;
                    $table_name = $wpdb->prefix . 'oyic_secure_login_otp';
                    $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name)) === $table_name;
                    ?>
                    <?php if ($table_exists): ?>
                        <span style="color: green;">✓ <?php echo esc_html__('Created', 'oyic-secure-login'); ?></span>
                    <?php else: ?>
                        <span style="color: red;">✗ <?php echo esc_html__('Missing', 'oyic-secure-login'); ?></span>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php echo esc_html__('Email Function', 'oyic-secure-login'); ?></th>
                <td>
                    <?php if (function_exists('wp_mail')): ?>
                        <span style="color: green;">✓ <?php echo esc_html__('Available', 'oyic-secure-login'); ?></span>
                        <button type="button" class="button test-email-button" style="margin-left: 10px;"><?php echo esc_html__('Test Email', 'oyic-secure-login'); ?></button>
                    <?php else: ?>
                        <span style="color: red;">✗ <?php echo esc_html__('Not Available', 'oyic-secure-login'); ?></span>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php echo esc_html__('Rewrite Rules', 'oyic-secure-login'); ?></th>
                <td>
                    <?php if (get_option('rewrite_rules')): ?>
                        <span style="color: green;">✓ <?php echo esc_html__('Active', 'oyic-secure-login'); ?></span>
                    <?php else: ?>
                        <span style="color: red;">✗ <?php echo esc_html__('Not Active', 'oyic-secure-login'); ?></span>
                        <button type="button" class="button flush-rules-button" style="margin-left: 10px;"><?php echo esc_html__('Flush Rules', 'oyic-secure-login'); ?></button>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
    </div>
    
    <div class="card" style="max-width: none; margin-top: 20px;">
        <h2><?php echo esc_html__('Instructions', 'oyic-secure-login'); ?></h2>
        <ol>
            <li><strong><?php echo esc_html__('Set your custom login slug', 'oyic-secure-login'); ?></strong> - <?php echo esc_html__('Choose a unique, hard-to-guess slug', 'oyic-secure-login'); ?></li>
            <li><strong><?php echo esc_html__('Save your override key', 'oyic-secure-login'); ?></strong> - <?php echo esc_html__('Keep this safe in case you need emergency access', 'oyic-secure-login'); ?></li>
            <li><strong><?php echo esc_html__('Test the custom login URL', 'oyic-secure-login'); ?></strong> - <?php echo esc_html__('Make sure it works before enabling protection', 'oyic-secure-login'); ?></li>
            <li><strong><?php echo esc_html__('Enable custom login URL', 'oyic-secure-login'); ?></strong> - <?php echo esc_html__('This will block the default wp-login.php', 'oyic-secure-login'); ?></li>
            <li><strong><?php echo esc_html__('Enable OTP login', 'oyic-secure-login'); ?></strong> (<?php echo esc_html__('optional', 'oyic-secure-login'); ?>) - <?php echo esc_html__('Allow email-based one-time password login', 'oyic-secure-login'); ?></li>
        </ol>
        
        <h3><?php echo esc_html__('Emergency Access', 'oyic-secure-login'); ?></h3>
        <p><?php echo esc_html__('If you\'re locked out, you can still access the original login page using:', 'oyic-secure-login'); ?></p>
        <code><?php echo esc_html($override_url); ?></code>
    </div>
</div>

<style>
.card h2 {
    margin-top: 0;
}

.form-table th {
    width: 200px;
}

code {
    background: #f1f1f1;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: monospace;
}
</style>
