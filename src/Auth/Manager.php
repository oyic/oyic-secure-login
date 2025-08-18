<?php
/**
 * Authentication Manager Class
 * 
 * Handles all authentication-related functionality including
 * OTP generation, verification, and login processing.
 * 
 * @package OYIC\SecureLogin\Auth
 * @since 1.0.0
 */

namespace OYIC\SecureLogin\Auth;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Authentication Manager
 * 
 * Manages authentication processes including OTP and standard login.
 * 
 * @since 1.0.0
 */
class Manager {

    /**
     * Plugin options
     * 
     * @since 1.0.0
     * @var array
     */
    private $options;

    /**
     * Database manager instance
     * 
     * @since 1.0.0
     * @var \OYIC\SecureLogin\Database\Manager
     */
    private $database;

    /**
     * Constructor
     * 
     * @since 1.0.0
     * @param array $options Plugin options
     */
    public function __construct($options = array()) {
        $this->options = $options;
        $this->database = oyic_secure_login()->get_component('database');
        $this->init();
    }

    /**
     * Initialize authentication functionality
     * 
     * @since 1.0.0
     * @return void
     */
    private function init() {
        // AJAX handlers for OTP
        add_action('wp_ajax_oyic_send_otp', array($this, 'handle_send_otp_ajax'));
        add_action('wp_ajax_nopriv_oyic_send_otp', array($this, 'handle_send_otp_ajax'));
        add_action('wp_ajax_oyic_verify_otp', array($this, 'handle_verify_otp_ajax'));
        add_action('wp_ajax_nopriv_oyic_verify_otp', array($this, 'handle_verify_otp_ajax'));

        // Handle login form processing
        add_action('init', array($this, 'process_login_form'));

        // Customize email headers for OTP emails
        add_filter('wp_mail', array($this, 'customize_otp_email'), 10, 1);

        // Add custom authentication method
        add_filter('authenticate', array($this, 'authenticate_otp'), 30, 3);

        // Cleanup expired OTPs regularly
        add_action('wp_scheduled_delete', array($this, 'cleanup_expired_otps'));
    }

    /**
     * Process login form submission
     * 
     * @since 1.0.0
     * @return void
     */
    public function process_login_form() {
        if (!oyic_secure_login_is_custom_login_page() || $_SERVER['REQUEST_METHOD'] !== 'POST') {
            return;
        }

        if (!isset($_POST['oyic_login_nonce']) || !wp_verify_nonce($_POST['oyic_login_nonce'], 'oyic_secure_login')) {
            $this->redirect_with_error('invalid_nonce', __('Security check failed.', 'oyic-secure-login'));
            return;
        }

        $login_type = sanitize_text_field($_POST['login_type'] ?? 'standard');

        switch ($login_type) {
            case 'standard':
                $this->process_standard_login();
                break;
            case 'otp_verify':
                $this->process_otp_verification();
                break;
            default:
                $this->redirect_with_error('invalid_type', __('Invalid login type.', 'oyic-secure-login'));
        }
    }

    /**
     * Process standard username/password login
     * 
     * @since 1.0.0
     * @return void
     */
    private function process_standard_login() {
        $username = sanitize_user($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $remember = !empty($_POST['remember']);

        if (empty($username) || empty($password)) {
            $this->redirect_with_error('empty_credentials', __('Username and password are required.', 'oyic-secure-login'));
            return;
        }

        // Rate limiting check
        if ($this->is_login_rate_limited($username)) {
            oyic_secure_login_log_event('login_rate_limited', 'Login attempt rate limited', array(
                'username' => $username,
            ));
            $this->redirect_with_error('rate_limited', __('Too many login attempts. Please try again later.', 'oyic-secure-login'));
            return;
        }

        $user = wp_authenticate($username, $password);

        if (is_wp_error($user)) {
            oyic_secure_login_log_event('login_failed', 'Standard login failed', array(
                'username' => $username,
                'error' => $user->get_error_code(),
            ));
            
            $this->track_failed_login($username);
            $this->redirect_with_error('login_failed', __('Invalid username or password.', 'oyic-secure-login'));
            return;
        }

        // Successful login
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, $remember);

        oyic_secure_login_log_event('login_success', 'Standard login successful', array(
            'user_id' => $user->ID,
            'username' => $user->user_login,
        ));

        $redirect_to = $this->get_redirect_url();
        wp_safe_redirect($redirect_to);
        exit;
    }

    /**
     * Process OTP verification
     * 
     * @since 1.0.0
     * @return void
     */
    private function process_otp_verification() {
        if (!oyic_secure_login_is_otp_enabled()) {
            $this->redirect_with_error('otp_disabled', __('OTP login is not enabled.', 'oyic-secure-login'));
            return;
        }

        $email = sanitize_email($_POST['email'] ?? '');
        $otp_code = sanitize_text_field($_POST['otp_code'] ?? '');

        if (empty($email) || empty($otp_code)) {
            $this->redirect_with_error('empty_otp', __('Email and OTP code are required.', 'oyic-secure-login'));
            return;
        }

        $verification_result = $this->verify_otp($email, $otp_code);

        if (!$verification_result['success']) {
            oyic_secure_login_log_event('otp_verification_failed', 'OTP verification failed', array(
                'email' => $email,
                'reason' => $verification_result['error'],
            ));
            
            $this->redirect_with_error('otp_invalid', $verification_result['message']);
            return;
        }

        // Get user by email
        $user = get_user_by('email', $email);
        if (!$user) {
            oyic_secure_login_log_event('otp_user_not_found', 'User not found for verified email', array(
                'email' => $email,
            ));
            
            $this->redirect_with_error('user_not_found', __('User account not found.', 'oyic-secure-login'));
            return;
        }

        // Successful OTP login
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, false); // Don't remember OTP logins

        oyic_secure_login_log_event('otp_login_success', 'OTP login successful', array(
            'user_id' => $user->ID,
            'email' => $email,
        ));

        $redirect_to = $this->get_redirect_url();
        wp_safe_redirect($redirect_to);
        exit;
    }

    /**
     * Handle send OTP AJAX request
     * 
     * @since 1.0.0
     * @return void
     */
    public function handle_send_otp_ajax() {
        if (!oyic_secure_login_is_otp_enabled()) {
            wp_send_json_error(__('OTP login is not enabled.', 'oyic-secure-login'));
        }

        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'oyic_send_otp')) {
            wp_send_json_error(__('Security check failed.', 'oyic-secure-login'));
        }

        $email = sanitize_email($_POST['email'] ?? '');

        if (empty($email) || !is_email($email)) {
            wp_send_json_error(__('Please enter a valid email address.', 'oyic-secure-login'));
        }

        // Check if user exists
        $user = get_user_by('email', $email);
        if (!$user) {
            // Don't reveal whether the email exists - security measure
            wp_send_json_success(__('If this email is registered, you will receive an OTP code shortly.', 'oyic-secure-login'));
        }

        // Rate limiting check
        if ($this->database && $this->database->is_rate_limited(
            $email,
            $this->options['rate_limit_attempts'] ?? 3,
            $this->options['rate_limit_window'] ?? 5
        )) {
            oyic_secure_login_log_event('otp_rate_limited', 'OTP request rate limited', array(
                'email' => $email,
            ));
            
            wp_send_json_error(__('Too many OTP requests. Please wait before requesting another code.', 'oyic-secure-login'));
        }

        $result = $this->send_otp($email);

        if ($result['success']) {
            wp_send_json_success($result['message']);
        } else {
            wp_send_json_error($result['message']);
        }
    }

    /**
     * Handle verify OTP AJAX request
     * 
     * @since 1.0.0
     * @return void
     */
    public function handle_verify_otp_ajax() {
        if (!oyic_secure_login_is_otp_enabled()) {
            wp_send_json_error(__('OTP login is not enabled.', 'oyic-secure-login'));
        }

        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'oyic_verify_otp')) {
            wp_send_json_error(__('Security check failed.', 'oyic-secure-login'));
        }

        $email = sanitize_email($_POST['email'] ?? '');
        $otp_code = sanitize_text_field($_POST['otp_code'] ?? '');

        if (empty($email) || empty($otp_code)) {
            wp_send_json_error(__('Email and OTP code are required.', 'oyic-secure-login'));
        }

        $result = $this->verify_otp($email, $otp_code);

        if ($result['success']) {
            wp_send_json_success($result['message']);
        } else {
            wp_send_json_error($result['message']);
        }
    }

    /**
     * Send OTP to email address
     * 
     * @since 1.0.0
     * @param string $email Email address
     * @return array Result array with success status and message
     */
    public function send_otp($email) {
        if (!$this->database) {
            return array(
                'success' => false,
                'message' => __('Database not available.', 'oyic-secure-login'),
            );
        }

        // Generate OTP code
        $otp_code = $this->generate_otp_code();
        $hashed_code = wp_hash_password($otp_code);

        // Store in database
        $expiry_minutes = $this->options['otp_expiry_minutes'] ?? 10;
        $stored = $this->database->store_otp($email, $hashed_code, $expiry_minutes);

        if (!$stored) {
            return array(
                'success' => false,
                'message' => __('Failed to generate OTP. Please try again.', 'oyic-secure-login'),
            );
        }

        // Send email
        $email_sent = $this->send_otp_email($email, $otp_code);

        if (!$email_sent) {
            return array(
                'success' => false,
                'message' => __('Failed to send OTP email. Please try again.', 'oyic-secure-login'),
            );
        }

        oyic_secure_login_log_event('otp_sent', 'OTP code sent', array(
            'email' => $email,
            'expiry_minutes' => $expiry_minutes,
        ));

        return array(
            'success' => true,
            'message' => __('OTP code sent to your email address.', 'oyic-secure-login'),
        );
    }

    /**
     * Verify OTP code
     * 
     * @since 1.0.0
     * @param string $email Email address
     * @param string $otp_code OTP code to verify
     * @return array Result array with success status and message
     */
    public function verify_otp($email, $otp_code) {
        if (!$this->database) {
            return array(
                'success' => false,
                'error' => 'database_unavailable',
                'message' => __('Database not available.', 'oyic-secure-login'),
            );
        }

        // Get stored OTP
        $stored_otp = $this->database->get_otp_by_email($email);

        if (!$stored_otp) {
            return array(
                'success' => false,
                'error' => 'no_otp_found',
                'message' => __('No valid OTP found. Please request a new code.', 'oyic-secure-login'),
            );
        }

        // Check if too many attempts
        if ($stored_otp->attempts >= 3) {
            $this->database->delete_otp($stored_otp->id);
            return array(
                'success' => false,
                'error' => 'too_many_attempts',
                'message' => __('Too many failed attempts. Please request a new code.', 'oyic-secure-login'),
            );
        }

        // Verify the code
        $is_valid = wp_check_password($otp_code, $stored_otp->otp_code);

        if (!$is_valid) {
            // Increment attempt counter
            $this->database->increment_otp_attempt($stored_otp->id);
            
            return array(
                'success' => false,
                'error' => 'invalid_code',
                'message' => __('Invalid OTP code. Please try again.', 'oyic-secure-login'),
            );
        }

        // Valid OTP - delete it to prevent reuse
        $this->database->delete_otp($stored_otp->id);

        return array(
            'success' => true,
            'message' => __('OTP verified successfully.', 'oyic-secure-login'),
        );
    }

    /**
     * Generate OTP code
     * 
     * @since 1.0.0
     * @return string 6-digit OTP code
     */
    private function generate_otp_code() {
        return str_pad(wp_rand(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Send OTP email
     * 
     * @since 1.0.0
     * @param string $email Recipient email
     * @param string $otp_code OTP code
     * @return bool True if sent successfully
     */
    private function send_otp_email($email, $otp_code) {
        $from_name = $this->options['email_from_name'] ?? get_bloginfo('name');
        $from_address = $this->options['email_from_address'] ?? get_option('admin_email');
        $expiry_minutes = $this->options['otp_expiry_minutes'] ?? 10;

        $subject = sprintf(
            /* translators: %s: Site name */
            __('Your login code for %s', 'oyic-secure-login'),
            get_bloginfo('name')
        );

        $message = $this->get_otp_email_template($otp_code, $expiry_minutes);

        $headers = array(
            'Content-Type: text/html; charset=UTF-8',
            sprintf('From: %s <%s>', $from_name, $from_address),
        );

        /**
         * Filter OTP email data before sending
         * 
         * @since 1.0.0
         * @param array $email_data Email data
         * @param string $email Recipient email
         * @param string $otp_code OTP code
         */
        $email_data = apply_filters('oyic_secure_login_otp_email', array(
            'to' => $email,
            'subject' => $subject,
            'message' => $message,
            'headers' => $headers,
        ), $email, $otp_code);

        return wp_mail(
            $email_data['to'],
            $email_data['subject'],
            $email_data['message'],
            $email_data['headers']
        );
    }

    /**
     * Get OTP email template
     * 
     * @since 1.0.0
     * @param string $otp_code OTP code
     * @param int $expiry_minutes Expiry time in minutes
     * @return string Email HTML content
     */
    private function get_otp_email_template($otp_code, $expiry_minutes) {
        $site_name = get_bloginfo('name');
        $site_url = home_url();
        $formatted_code = oyic_secure_login_format_otp_code($otp_code);

        ob_start();
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title><?php echo esc_html__('Login Code', 'oyic-secure-login'); ?></title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { text-align: center; border-bottom: 2px solid #0073aa; padding-bottom: 20px; margin-bottom: 30px; }
                .otp-code { font-size: 32px; font-weight: bold; text-align: center; background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 30px 0; letter-spacing: 3px; }
                .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .footer { text-align: center; font-size: 12px; color: #666; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 20px; }
                .warning { color: #d32f2f; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1><?php echo esc_html($site_name); ?></h1>
                    <p><?php echo esc_html__('Secure Login Code', 'oyic-secure-login'); ?></p>
                </div>

                <p><?php echo esc_html__('Hello,', 'oyic-secure-login'); ?></p>
                
                <p><?php echo esc_html__('You requested a login code for your account. Use the code below to complete your login:', 'oyic-secure-login'); ?></p>

                <div class="otp-code"><?php echo esc_html($formatted_code); ?></div>

                <div class="info">
                    <p><strong><?php echo esc_html__('Important:', 'oyic-secure-login'); ?></strong></p>
                    <ul>
                        <li><?php printf(
                            /* translators: %d: Number of minutes */
                            esc_html__('This code expires in %d minutes', 'oyic-secure-login'),
                            $expiry_minutes
                        ); ?></li>
                        <li><?php echo esc_html__('Use this code only once', 'oyic-secure-login'); ?></li>
                        <li><?php echo esc_html__('Do not share this code with anyone', 'oyic-secure-login'); ?></li>
                    </ul>
                </div>

                <p class="warning"><?php echo esc_html__('If you did not request this code, please ignore this email and consider changing your password.', 'oyic-secure-login'); ?></p>

                <div class="footer">
                    <p><?php echo esc_html__('This email was sent automatically from', 'oyic-secure-login'); ?> <a href="<?php echo esc_url($site_url); ?>"><?php echo esc_html($site_name); ?></a></p>
                    <p><?php echo esc_html__('OYIC Secure Login Plugin', 'oyic-secure-login'); ?></p>
                </div>
            </div>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    /**
     * Customize OTP email headers
     * 
     * @since 1.0.0
     * @param array $args Email arguments
     * @return array Modified email arguments
     */
    public function customize_otp_email($args) {
        // Only modify emails that contain OTP in subject
        if (strpos($args['subject'], 'login code') !== false) {
            $args['headers'][] = 'X-Mailer: OYIC Secure Login';
            $args['headers'][] = 'X-Priority: 1';
        }

        return $args;
    }

    /**
     * Custom OTP authentication method
     * 
     * @since 1.0.0
     * @param \WP_User|\WP_Error|null $user User object or error
     * @param string $username Username
     * @param string $password Password
     * @return \WP_User|\WP_Error User object or error
     */
    public function authenticate_otp($user, $username, $password) {
        // Only handle if no user found yet and OTP is enabled
        if ($user instanceof \WP_User || !oyic_secure_login_is_otp_enabled()) {
            return $user;
        }

        // Check if this is an OTP authentication attempt
        if (strpos($password, 'otp:') === 0) {
            $otp_code = substr($password, 4);
            $email = $username;

            $result = $this->verify_otp($email, $otp_code);
            
            if ($result['success']) {
                $user_obj = get_user_by('email', $email);
                if ($user_obj) {
                    return $user_obj;
                }
            }

            return new \WP_Error('invalid_otp', $result['message']);
        }

        return $user;
    }

    /**
     * Check if login is rate limited
     * 
     * @since 1.0.0
     * @param string $username Username or email
     * @return bool True if rate limited
     */
    private function is_login_rate_limited($username) {
        $transient_key = 'oyic_login_attempts_' . md5($username . oyic_secure_login_get_client_ip());
        $attempts = get_transient($transient_key);

        if ($attempts === false) {
            return false;
        }

        return $attempts >= 5; // Max 5 attempts per 15 minutes
    }

    /**
     * Track failed login attempt
     * 
     * @since 1.0.0
     * @param string $username Username or email
     * @return void
     */
    private function track_failed_login($username) {
        $transient_key = 'oyic_login_attempts_' . md5($username . oyic_secure_login_get_client_ip());
        $attempts = get_transient($transient_key);

        if ($attempts === false) {
            $attempts = 0;
        }

        $attempts++;
        set_transient($transient_key, $attempts, 15 * MINUTE_IN_SECONDS);
    }

    /**
     * Get redirect URL after login
     * 
     * @since 1.0.0
     * @return string Redirect URL
     */
    private function get_redirect_url() {
        $redirect_to = isset($_POST['redirect_to']) ? esc_url_raw($_POST['redirect_to']) : '';
        
        if (empty($redirect_to)) {
            $redirect_to = admin_url();
        }

        /**
         * Filter login redirect URL
         * 
         * @since 1.0.0
         * @param string $redirect_to Redirect URL
         */
        return apply_filters('oyic_secure_login_redirect_url', $redirect_to);
    }

    /**
     * Redirect with error message
     * 
     * @since 1.0.0
     * @param string $error_code Error code
     * @param string $message Error message
     * @return void
     */
    private function redirect_with_error($error_code, $message) {
        $url = oyic_secure_login_get_login_url(array(
            'error' => $error_code,
            'message' => urlencode($message),
        ));

        wp_safe_redirect($url);
        exit;
    }

    /**
     * Cleanup expired OTPs
     * 
     * @since 1.0.0
     * @return void
     */
    public function cleanup_expired_otps() {
        if ($this->database) {
            $this->database->cleanup_expired_otps();
        }
    }
}
