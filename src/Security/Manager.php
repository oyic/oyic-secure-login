<?php
/**
 * Security Manager Class
 * 
 * Handles security-related functionality including rate limiting,
 * IP blocking, brute force protection, and security monitoring.
 * 
 * @package OYIC\SecureLogin\Security
 * @since 1.0.0
 */

namespace OYIC\SecureLogin\Security;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Security Manager
 * 
 * Manages security features and protection mechanisms.
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
     * Blocked IPs cache
     * 
     * @since 1.0.0
     * @var array
     */
    private $blocked_ips = array();

    /**
     * Constructor
     * 
     * @since 1.0.0
     * @param array $options Plugin options
     */
    public function __construct($options = array()) {
        $this->options = $options;
        $this->init();
    }

    /**
     * Initialize security functionality
     * 
     * @since 1.0.0
     * @return void
     */
    private function init() {
        // Block default login access if custom login is enabled
        add_action('init', array($this, 'block_default_login'), 1);
        
        // Add security headers
        add_action('send_headers', array($this, 'add_security_headers'));
        
        // Monitor failed login attempts
        add_action('wp_login_failed', array($this, 'handle_failed_login'));
        
        // Monitor successful logins
        add_action('wp_login', array($this, 'handle_successful_login'), 10, 2);
        
        // Block suspicious requests
        add_action('init', array($this, 'check_request_security'), 5);
        
        // Hide WordPress version
        remove_action('wp_head', 'wp_generator');
        add_filter('the_generator', '__return_empty_string');
        
        // Disable XML-RPC if not needed
        add_filter('xmlrpc_enabled', array($this, 'disable_xmlrpc'));
        
        // Remove unnecessary meta tags
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'rsd_link');
        
        // Prevent user enumeration
        add_action('init', array($this, 'prevent_user_enumeration'));
        
        // Add custom login error messages
        add_filter('login_errors', array($this, 'customize_login_errors'));
        
        // Schedule cleanup tasks
        if (!wp_next_scheduled('oyic_security_cleanup')) {
            wp_schedule_event(time(), 'daily', 'oyic_security_cleanup');
        }
        add_action('oyic_security_cleanup', array($this, 'daily_cleanup'));
    }

    /**
     * Block default login access
     * 
     * @since 1.0.0
     * @return void
     */
    public function block_default_login() {
        if (!oyic_secure_login_is_custom_login_enabled()) {
            return;
        }

        global $pagenow;

        // Allow override access
        if (isset($_GET['override']) && $_GET['override'] === ($this->options['override_key'] ?? '')) {
            return;
        }

        // Allow AJAX requests
        if (wp_doing_ajax()) {
            return;
        }

        // Allow logged-in users to access admin
        if (is_admin() && is_user_logged_in()) {
            return;
        }

        // Block wp-login.php access
        if ($pagenow === 'wp-login.php') {
            oyic_secure_login_log_event('blocked_default_login', 'Blocked access to wp-login.php', array(
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'referer' => $_SERVER['HTTP_REFERER'] ?? '',
            ));
            
            $this->block_request(__('Access denied.', 'oyic-secure-login'));
        }

        // Block admin access for non-logged-in users
        if (is_admin() && !is_user_logged_in()) {
            oyic_secure_login_log_event('blocked_admin_access', 'Blocked admin access for non-logged-in user');
            $this->block_request(__('Access denied.', 'oyic-secure-login'));
        }
    }

    /**
     * Add security headers
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_security_headers() {
        if (!headers_sent()) {
            // Prevent clickjacking
            header('X-Frame-Options: SAMEORIGIN');
            
            // Prevent MIME type sniffing
            header('X-Content-Type-Options: nosniff');
            
            // XSS protection
            header('X-XSS-Protection: 1; mode=block');
            
            // Referrer policy
            header('Referrer-Policy: strict-origin-when-cross-origin');
            
            // Remove server signature
            header_remove('Server');
            header_remove('X-Powered-By');
        }
    }

    /**
     * Handle failed login attempts
     * 
     * @since 1.0.0
     * @param string $username Username that failed login
     * @return void
     */
    public function handle_failed_login($username) {
        $ip = oyic_secure_login_get_client_ip();
        
        oyic_secure_login_log_event('login_failed', 'Failed login attempt', array(
            'username' => $username,
            'ip' => $ip,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ));

        // Track failed attempts by IP
        $this->track_failed_attempt($ip);
        
        // Track failed attempts by username
        $this->track_failed_attempt($username, 'username');
        
        // Check if IP should be blocked
        $this->check_and_block_ip($ip);
    }

    /**
     * Handle successful login
     * 
     * @since 1.0.0
     * @param string $user_login Username
     * @param \WP_User $user User object
     * @return void
     */
    public function handle_successful_login($user_login, $user) {
        $ip = oyic_secure_login_get_client_ip();
        
        oyic_secure_login_log_event('login_success', 'Successful login', array(
            'user_id' => $user->ID,
            'username' => $user_login,
            'ip' => $ip,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ));

        // Clear failed attempts for this IP and username
        $this->clear_failed_attempts($ip);
        $this->clear_failed_attempts($user_login, 'username');
    }

    /**
     * Check request security
     * 
     * @since 1.0.0
     * @return void
     */
    public function check_request_security() {
        $ip = oyic_secure_login_get_client_ip();
        
        // Check if IP is blocked
        if ($this->is_ip_blocked($ip)) {
            oyic_secure_login_log_event('blocked_ip_request', 'Blocked request from banned IP', array(
                'ip' => $ip,
            ));
            
            $this->block_request(__('Your IP address has been blocked due to suspicious activity.', 'oyic-secure-login'));
        }

        // Check for suspicious user agents
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if ($this->is_suspicious_user_agent($user_agent)) {
            oyic_secure_login_log_event('suspicious_user_agent', 'Suspicious user agent detected', array(
                'user_agent' => $user_agent,
                'ip' => $ip,
            ));
            
            // Don't block immediately, just log and monitor
        }

        // Check for suspicious request patterns
        if ($this->is_suspicious_request()) {
            oyic_secure_login_log_event('suspicious_request', 'Suspicious request pattern detected', array(
                'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
                'query_string' => $_SERVER['QUERY_STRING'] ?? '',
                'ip' => $ip,
            ));
        }
    }

    /**
     * Track failed attempts
     * 
     * @since 1.0.0
     * @param string $identifier IP address or username
     * @param string $type Type of tracking (ip or username)
     * @return void
     */
    private function track_failed_attempt($identifier, $type = 'ip') {
        $transient_key = 'oyic_failed_' . $type . '_' . md5($identifier);
        $attempts = get_transient($transient_key);
        
        if ($attempts === false) {
            $attempts = array();
        }
        
        $attempts[] = time();
        
        // Keep only attempts from last hour
        $one_hour_ago = time() - HOUR_IN_SECONDS;
        $attempts = array_filter($attempts, function($timestamp) use ($one_hour_ago) {
            return $timestamp > $one_hour_ago;
        });
        
        set_transient($transient_key, $attempts, HOUR_IN_SECONDS);
    }

    /**
     * Clear failed attempts
     * 
     * @since 1.0.0
     * @param string $identifier IP address or username
     * @param string $type Type of tracking (ip or username)
     * @return void
     */
    private function clear_failed_attempts($identifier, $type = 'ip') {
        $transient_key = 'oyic_failed_' . $type . '_' . md5($identifier);
        delete_transient($transient_key);
    }

    /**
     * Check and block IP if necessary
     * 
     * @since 1.0.0
     * @param string $ip IP address
     * @return void
     */
    private function check_and_block_ip($ip) {
        $transient_key = 'oyic_failed_ip_' . md5($ip);
        $attempts = get_transient($transient_key);
        
        if (is_array($attempts) && count($attempts) >= 5) {
            // Block IP for 24 hours
            $this->block_ip($ip, 24 * HOUR_IN_SECONDS);
            
            oyic_secure_login_log_event('ip_blocked', 'IP blocked due to failed attempts', array(
                'ip' => $ip,
                'attempts' => count($attempts),
            ));
        }
    }

    /**
     * Block an IP address
     * 
     * @since 1.0.0
     * @param string $ip IP address
     * @param int $duration Block duration in seconds
     * @return void
     */
    private function block_ip($ip, $duration = DAY_IN_SECONDS) {
        $blocked_ips = get_option('oyic_blocked_ips', array());
        $blocked_ips[$ip] = time() + $duration;
        update_option('oyic_blocked_ips', $blocked_ips);
        
        // Cache for this request
        $this->blocked_ips[$ip] = $blocked_ips[$ip];
    }

    /**
     * Check if IP is blocked
     * 
     * @since 1.0.0
     * @param string $ip IP address
     * @return bool True if blocked
     */
    private function is_ip_blocked($ip) {
        // Check cache first
        if (isset($this->blocked_ips[$ip])) {
            return $this->blocked_ips[$ip] > time();
        }
        
        $blocked_ips = get_option('oyic_blocked_ips', array());
        
        if (isset($blocked_ips[$ip])) {
            $blocked_until = $blocked_ips[$ip];
            
            if ($blocked_until > time()) {
                $this->blocked_ips[$ip] = $blocked_until;
                return true;
            } else {
                // Block expired, remove it
                unset($blocked_ips[$ip]);
                update_option('oyic_blocked_ips', $blocked_ips);
            }
        }
        
        return false;
    }

    /**
     * Check for suspicious user agent
     * 
     * @since 1.0.0
     * @param string $user_agent User agent string
     * @return bool True if suspicious
     */
    private function is_suspicious_user_agent($user_agent) {
        if (empty($user_agent)) {
            return true;
        }
        
        $suspicious_patterns = array(
            'bot', 'crawler', 'spider', 'scraper', 'scanner',
            'sqlmap', 'nikto', 'masscan', 'nmap', 'wget',
            'curl', 'python', 'perl', 'java/', 'go-http-client'
        );
        
        $user_agent_lower = strtolower($user_agent);
        
        foreach ($suspicious_patterns as $pattern) {
            if (strpos($user_agent_lower, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check for suspicious request patterns
     * 
     * @since 1.0.0
     * @return bool True if suspicious
     */
    private function is_suspicious_request() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        
        // Check for common attack patterns
        $suspicious_patterns = array(
            // SQL injection
            'union.*select', 'drop.*table', 'insert.*into', 'delete.*from',
            // XSS
            '<script', 'javascript:', 'onload=', 'onerror=',
            // Path traversal
            '../', '..\\', '/etc/passwd', '/proc/self/environ',
            // Command injection
            ';cat ', ';ls ', ';id ', '|cat ', '|ls ',
            // File inclusion
            'php://input', 'php://filter', 'data://',
        );
        
        $content = strtolower($request_uri . ' ' . $query_string);
        
        foreach ($suspicious_patterns as $pattern) {
            if (preg_match('/' . preg_quote($pattern, '/') . '/i', $content)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Block request with error page
     * 
     * @since 1.0.0
     * @param string $message Error message
     * @return void
     */
    private function block_request($message = '') {
        if (empty($message)) {
            $message = __('Access denied.', 'oyic-secure-login');
        }
        
        status_header(403);
        nocache_headers();
        
        wp_die(
            esc_html($message),
            __('Access Denied', 'oyic-secure-login'),
            array(
                'response' => 403,
                'back_link' => true,
            )
        );
    }

    /**
     * Disable XML-RPC
     * 
     * @since 1.0.0
     * @param bool $enabled Whether XML-RPC is enabled
     * @return bool Always false
     */
    public function disable_xmlrpc($enabled) {
        return false;
    }

    /**
     * Prevent user enumeration
     * 
     * @since 1.0.0
     * @return void
     */
    public function prevent_user_enumeration() {
        if (isset($_GET['author'])) {
            oyic_secure_login_log_event('user_enumeration_attempt', 'User enumeration attempt blocked', array(
                'author_param' => $_GET['author'],
            ));
            
            wp_redirect(home_url());
            exit;
        }
    }

    /**
     * Customize login error messages
     * 
     * @since 1.0.0
     * @param string $error Error message
     * @return string Modified error message
     */
    public function customize_login_errors($error) {
        // Don't reveal whether username exists
        if (strpos($error, 'Invalid username') !== false || 
            strpos($error, 'incorrect password') !== false) {
            return __('Invalid login credentials.', 'oyic-secure-login');
        }
        
        return $error;
    }

    /**
     * Daily cleanup task
     * 
     * @since 1.0.0
     * @return void
     */
    public function daily_cleanup() {
        // Clean up expired blocked IPs
        $blocked_ips = get_option('oyic_blocked_ips', array());
        $current_time = time();
        $cleaned = false;
        
        foreach ($blocked_ips as $ip => $blocked_until) {
            if ($blocked_until < $current_time) {
                unset($blocked_ips[$ip]);
                $cleaned = true;
            }
        }
        
        if ($cleaned) {
            update_option('oyic_blocked_ips', $blocked_ips);
        }
        
        // Clean up old transients
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_oyic_failed_%' AND option_value < " . $current_time);
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_oyic_failed_%' AND option_value < " . $current_time);
        
        oyic_secure_login_log_event('security_cleanup', 'Daily security cleanup completed', array(
            'blocked_ips_cleaned' => $cleaned,
        ));
    }

    /**
     * Get security statistics
     * 
     * @since 1.0.0
     * @param int $days Number of days to analyze
     * @return array Security statistics
     */
    public function get_security_statistics($days = 30) {
        $stats = array(
            'blocked_requests' => 0,
            'failed_logins' => 0,
            'blocked_ips' => 0,
            'suspicious_requests' => 0,
        );
        
        // This would typically query a security log table
        // For now, return basic stats from options
        $blocked_ips = get_option('oyic_blocked_ips', array());
        $stats['blocked_ips'] = count($blocked_ips);
        
        /**
         * Filter security statistics
         * 
         * @since 1.0.0
         * @param array $stats Statistics array
         * @param int $days Number of days analyzed
         */
        return apply_filters('oyic_secure_login_security_stats', $stats, $days);
    }

    /**
     * Unblock an IP address
     * 
     * @since 1.0.0
     * @param string $ip IP address to unblock
     * @return bool True if unblocked successfully
     */
    public function unblock_ip($ip) {
        $blocked_ips = get_option('oyic_blocked_ips', array());
        
        if (isset($blocked_ips[$ip])) {
            unset($blocked_ips[$ip]);
            update_option('oyic_blocked_ips', $blocked_ips);
            
            // Clear cache
            unset($this->blocked_ips[$ip]);
            
            oyic_secure_login_log_event('ip_unblocked', 'IP address manually unblocked', array(
                'ip' => $ip,
            ));
            
            return true;
        }
        
        return false;
    }

    /**
     * Get blocked IPs list
     * 
     * @since 1.0.0
     * @return array Blocked IPs with expiration times
     */
    public function get_blocked_ips() {
        return get_option('oyic_blocked_ips', array());
    }

    /**
     * Check if current request is from blocked IP
     * 
     * @since 1.0.0
     * @return bool True if current IP is blocked
     */
    public function is_current_ip_blocked() {
        return $this->is_ip_blocked(oyic_secure_login_get_client_ip());
    }
}
