<?php
/**
 * Direct Admin Page Template for OYIC Secure Login
 * 
 * This template bypasses the Admin Manager class and works directly
 * with the WordPress Settings API.
 * 
 * @package OYIC\SecureLogin
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}
?>

<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
    
    <div class="notice notice-info">
        <p><strong>OYIC Secure Login</strong> - Enhanced WordPress security with custom login URLs and email OTP authentication.</p>
    </div>
    
    <form method="post" action="options.php">
        <?php
        settings_fields('oyic_secure_login_settings');
        do_settings_sections('oyic-secure-login');
        submit_button();
        ?>
    </form>
    
    <div class="postbox" style="margin-top: 20px;">
        <h2 class="hndle" style="padding: 10px 15px; margin: 0;">System Status</h2>
        <div class="inside" style="padding: 15px;">
            <?php
            // Get plugin options
            $options = get_option('oyic_secure_login_options', array());
            
            // Check database table
            global $wpdb;
            $table_name = $wpdb->prefix . 'oyic_secure_login_otp';
            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name;
            
            // Check email function
            $email_available = function_exists('wp_mail');
            
            // Check blocking status
            $blocking_enabled = isset($options['enable_custom_login']) ? $options['enable_custom_login'] : 0;
            $otp_enabled = isset($options['enable_otp_login']) ? $options['enable_otp_login'] : 0;
            $custom_url = isset($options['custom_login_url']) ? $options['custom_login_url'] : 'secure-access';
            
            // Check if custom URL rewrite rule exists
            $rules = get_option('rewrite_rules');
            $rule_exists = isset($rules[$custom_url . '/?$']);
            ?>
            
            <table class="widefat">
                <tbody>
                    <tr>
                        <td><strong>Database Table</strong></td>
                        <td>
                            <?php if ($table_exists): ?>
                                <span style="color: green;">✓ OTP table exists</span>
                            <?php else: ?>
                                <span style="color: red;">✗ OTP table missing</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Email Function</strong></td>
                        <td>
                            <?php if ($email_available): ?>
                                <span style="color: green;">✓ wp_mail() available</span>
                            <?php else: ?>
                                <span style="color: red;">✗ wp_mail() not available</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Login Blocking</strong></td>
                        <td>
                            <?php if ($blocking_enabled): ?>
                                <span style="color: green;">✓ Access blocking enabled</span>
                            <?php else: ?>
                                <span style="color: orange;">⚠ Access blocking disabled</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Custom Login URL</strong></td>
                        <td>
                            <?php if ($blocking_enabled && $rule_exists): ?>
                                <span style="color: green;">✓ Active: </span>
                                <code><?php echo esc_html(home_url('/' . $custom_url . '/')); ?></code>
                            <?php elseif ($blocking_enabled && !$rule_exists): ?>
                                <span style="color: red;">✗ Rewrite rules missing</span>
                            <?php else: ?>
                                <span style="color: orange;">⚠ Custom URL disabled</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>OTP Access</strong></td>
                        <td>
                            <?php if ($otp_enabled): ?>
                                <span style="color: green;">✓ Email OTP enabled</span>
                            <?php else: ?>
                                <span style="color: orange;">⚠ Email OTP disabled</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Plugin Version</strong></td>
                        <td><?php echo esc_html(OYIC_SECURE_LOGIN_VERSION); ?></td>
                    </tr>
                </tbody>
            </table>
            
            <p style="margin-top: 15px;">
                <button type="button" class="button" onclick="location.reload()">Refresh Status</button>
                <button type="button" class="button" onclick="flushRewriteRules()" style="margin-left: 10px;">Flush Rewrite Rules</button>
            </p>
        </div>
    </div>
</div>

<style>
.widefat td {
    padding: 10px;
    border-bottom: 1px solid #ddd;
}
.widefat td:first-child {
    width: 200px;
    font-weight: 500;
}
.override-key-section {
    margin-bottom: 10px;
}
.emergency-url-section {
    background: #f9f9f9;
    padding: 15px;
    border: 1px solid #ddd;
    border-radius: 4px;
}
.emergency-url-section label {
    color: #333;
    font-weight: 600;
}
#emergency_url_field {
    font-family: monospace;
    font-size: 12px;
    background: #fff;
}
</style>

<script>
function generateOverrideKey() {
    const button = event.target;
    const originalText = button.textContent;
    button.textContent = 'Generating...';
    button.disabled = true;
    
    // AJAX request to generate new key
    const data = new FormData();
    data.append('action', 'oyic_generate_key');
    data.append('nonce', '<?php echo wp_create_nonce('oyic_secure_login_admin'); ?>');
    
    fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
        method: 'POST',
        body: data
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            // Update the key input field
            const keyInput = document.getElementById('override_key_field');
            if (keyInput) {
                keyInput.value = result.data.key;
            }
            
            // Update the emergency URL input field
            const urlInput = document.getElementById('emergency_url_field');
            if (urlInput) {
                urlInput.value = result.data.emergency_url;
            }
            
            // Update any description displays (for backwards compatibility)
            const descriptions = document.querySelectorAll('.description');
            descriptions.forEach(desc => {
                if (desc.innerHTML.includes('Emergency access URL:')) {
                    desc.innerHTML = desc.innerHTML.replace(
                        /Emergency access URL: <code>.*?<\/code>/,
                        'Emergency access URL: <code>' + result.data.emergency_url + '</code>'
                    );
                }
            });
            
            alert('New override key generated and saved successfully!\n\nNew Emergency URL: ' + result.data.emergency_url);
        } else {
            alert('Error generating key: ' + (result.data || 'Unknown error'));
        }
    })
    .catch(error => {
        alert('Error generating key: ' + error.message);
    })
    .finally(() => {
        button.textContent = originalText;
        button.disabled = false;
    });
}

function copyOverrideKey() {
    const keyInput = document.getElementById('override_key_field');
    if (keyInput) {
        keyInput.select();
        keyInput.setSelectionRange(0, 99999); // For mobile devices
        
        try {
            document.execCommand('copy');
            alert('Override key copied to clipboard!');
        } catch (err) {
            // Fallback for modern browsers
            navigator.clipboard.writeText(keyInput.value).then(() => {
                alert('Override key copied to clipboard!');
            }).catch(() => {
                alert('Failed to copy. Please select and copy manually.');
            });
        }
    }
}

function copyEmergencyURL() {
    const urlInput = document.getElementById('emergency_url_field');
    if (urlInput) {
        urlInput.select();
        urlInput.setSelectionRange(0, 99999); // For mobile devices
        
        try {
            document.execCommand('copy');
            alert('Emergency URL copied to clipboard!');
        } catch (err) {
            // Fallback for modern browsers
            navigator.clipboard.writeText(urlInput.value).then(() => {
                alert('Emergency URL copied to clipboard!');
            }).catch(() => {
                alert('Failed to copy. Please select and copy manually.');
            });
        }
    }
}

function testEmail() {
    const emailInput = document.querySelector('input[name="oyic_secure_login_options[email_from_address]"]');
    const email = emailInput ? emailInput.value : '';
    
    if (!email) {
        alert('Please enter an email address first.');
        return;
    }
    
    // For now, just show a message
    alert('Test email functionality will send a test email to: ' + email + '\n\nThis feature requires AJAX implementation.');
}

function flushRewriteRules() {
    if (confirm('This will flush WordPress rewrite rules to update your custom login URL. Continue?')) {
        // For now, just show a message
        alert('Please save your settings first, then deactivate and reactivate the plugin to update rewrite rules.');
    }
}
</script>
