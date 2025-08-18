<?php
/**
 * Database Manager Class
 * 
 * Handles database operations including table creation, migrations,
 * and data management for the OYIC Secure Login plugin.
 * 
 * @package OYIC\SecureLogin\Database
 * @since 1.0.0
 */

namespace OYIC\SecureLogin\Database;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Database Manager
 * 
 * Manages all database operations for the plugin including
 * table creation, data storage, and cleanup operations.
 * 
 * @since 1.0.0
 */
class Manager {

    /**
     * Database version
     * 
     * @since 1.0.0
     * @var string
     */
    const DB_VERSION = '1.0.0';

    /**
     * OTP table name
     * 
     * @since 1.0.0
     * @var string
     */
    private $otp_table;

    /**
     * WordPress database instance
     * 
     * @since 1.0.0
     * @var \wpdb
     */
    private $wpdb;

    /**
     * Constructor
     * 
     * Initializes the database manager and sets up table names.
     * 
     * @since 1.0.0
     */
    public function __construct() {
        global $wpdb;
        
        $this->wpdb = $wpdb;
        $this->otp_table = $this->wpdb->prefix . 'oyic_secure_login_otp';
        
        // Check if database needs updating
        add_action('admin_init', array($this, 'check_database_version'));
    }

    /**
     * Create database tables
     * 
     * Creates all required database tables for the plugin.
     * Uses dbDelta for safe table creation and updates.
     * 
     * @since 1.0.0
     * @return bool True on success, false on failure
     */
    public function create_tables() {
        $charset_collate = $this->wpdb->get_charset_collate();
        
        // OTP table for storing one-time passwords
        $otp_table_sql = "CREATE TABLE {$this->otp_table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            email varchar(255) NOT NULL,
            otp_code varchar(255) NOT NULL,
            expires_at datetime NOT NULL,
            created_at datetime NOT NULL,
            attempts int(3) unsigned DEFAULT 0,
            ip_address varchar(45) DEFAULT '',
            user_agent text DEFAULT '',
            PRIMARY KEY (id),
            KEY email (email),
            KEY expires_at (expires_at),
            KEY created_at (created_at),
            KEY ip_address (ip_address)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        
        // Suppress any potential output from dbDelta
        ob_start();
        $result = dbDelta($otp_table_sql);
        ob_end_clean();
        
        // Update database version
        update_option('oyic_secure_login_db_version', self::DB_VERSION);
        
        /**
         * Fires after database tables are created
         * 
         * @since 1.0.0
         * @param array $result dbDelta result
         */
        do_action('oyic_secure_login_tables_created', $result);
        
        return !empty($result);
    }

    /**
     * Check database version
     * 
     * Checks if the database needs to be updated and runs
     * migrations if necessary.
     * 
     * @since 1.0.0
     * @return void
     */
    public function check_database_version() {
        $current_version = get_option('oyic_secure_login_db_version', '0.0.0');
        
        if (version_compare($current_version, self::DB_VERSION, '<')) {
            $this->run_migrations($current_version);
        }
    }

    /**
     * Run database migrations
     * 
     * Runs necessary database migrations based on the current version.
     * 
     * @since 1.0.0
     * @param string $from_version Current database version
     * @return void
     */
    private function run_migrations($from_version) {
        // Future migrations can be added here
        
        // For now, just recreate tables
        $this->create_tables();
        
        /**
         * Fires after database migrations are complete
         * 
         * @since 1.0.0
         * @param string $from_version Previous version
         * @param string $to_version New version
         */
        do_action('oyic_secure_login_migrations_complete', $from_version, self::DB_VERSION);
    }

    /**
     * Store OTP code
     * 
     * Stores an OTP code in the database with expiration time
     * and user context information.
     * 
     * @since 1.0.0
     * @param string $email User email address
     * @param string $otp_code Hashed OTP code
     * @param int $expiry_minutes Minutes until expiration
     * @return int|false Insert ID on success, false on failure
     */
    public function store_otp($email, $otp_code, $expiry_minutes = 10) {
        // Clean up expired OTPs first
        $this->cleanup_expired_otps();
        
        // Delete any existing OTP for this email
        $this->delete_otp_by_email($email);
        
        $expires_at = gmdate('Y-m-d H:i:s', time() + ($expiry_minutes * 60));
        $created_at = current_time('mysql', true);
        
        $result = $this->wpdb->insert(
            $this->otp_table,
            array(
                'email' => sanitize_email($email),
                'otp_code' => $otp_code, // Already hashed
                'expires_at' => $expires_at,
                'created_at' => $created_at,
                'attempts' => 0,
                'ip_address' => oyic_secure_login_get_client_ip(),
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 500) : '',
            ),
            array(
                '%s', // email
                '%s', // otp_code
                '%s', // expires_at
                '%s', // created_at
                '%d', // attempts
                '%s', // ip_address
                '%s', // user_agent
            )
        );
        
        if ($result === false) {
            oyic_secure_login_log_event('otp_store_failed', 'Failed to store OTP', array(
                'email' => $email,
                'error' => $this->wpdb->last_error,
            ));
            return false;
        }
        
        oyic_secure_login_log_event('otp_stored', 'OTP stored successfully', array(
            'email' => $email,
            'expires_at' => $expires_at,
        ));
        
        return $this->wpdb->insert_id;
    }

    /**
     * Get OTP by email
     * 
     * Retrieves the most recent valid OTP for the given email address.
     * 
     * @since 1.0.0
     * @param string $email User email address
     * @return object|null OTP record or null if not found
     */
    public function get_otp_by_email($email) {
        $otp = $this->wpdb->get_row(
            $this->wpdb->prepare(
                "SELECT * FROM {$this->otp_table} 
                 WHERE email = %s 
                 AND expires_at > %s 
                 ORDER BY created_at DESC 
                 LIMIT 1",
                sanitize_email($email),
                current_time('mysql', true)
            )
        );
        
        return $otp ?: null;
    }

    /**
     * Increment OTP attempt
     * 
     * Increments the attempt counter for an OTP record.
     * 
     * @since 1.0.0
     * @param int $otp_id OTP record ID
     * @return bool True on success, false on failure
     */
    public function increment_otp_attempt($otp_id) {
        $result = $this->wpdb->query(
            $this->wpdb->prepare(
                "UPDATE {$this->otp_table} 
                 SET attempts = attempts + 1 
                 WHERE id = %d",
                $otp_id
            )
        );
        
        return $result !== false;
    }

    /**
     * Delete OTP by ID
     * 
     * Deletes a specific OTP record by its ID.
     * 
     * @since 1.0.0
     * @param int $otp_id OTP record ID
     * @return bool True on success, false on failure
     */
    public function delete_otp($otp_id) {
        $result = $this->wpdb->delete(
            $this->otp_table,
            array('id' => $otp_id),
            array('%d')
        );
        
        return $result !== false;
    }

    /**
     * Delete OTP by email
     * 
     * Deletes all OTP records for a specific email address.
     * 
     * @since 1.0.0
     * @param string $email User email address
     * @return bool True on success, false on failure
     */
    public function delete_otp_by_email($email) {
        $result = $this->wpdb->delete(
            $this->otp_table,
            array('email' => sanitize_email($email)),
            array('%s')
        );
        
        return $result !== false;
    }

    /**
     * Cleanup expired OTPs
     * 
     * Removes all expired OTP records from the database.
     * This method is called automatically but can also be run manually.
     * 
     * @since 1.0.0
     * @return int Number of records deleted
     */
    public function cleanup_expired_otps() {
        $deleted = $this->wpdb->query(
            $this->wpdb->prepare(
                "DELETE FROM {$this->otp_table} WHERE expires_at < %s",
                current_time('mysql', true)
            )
        );
        
        if ($deleted > 0) {
            oyic_secure_login_log_event('otp_cleanup', 'Expired OTPs cleaned up', array(
                'deleted_count' => $deleted,
            ));
        }
        
        return $deleted ?: 0;
    }

    /**
     * Get OTP statistics
     * 
     * Returns statistics about OTP usage for monitoring and analysis.
     * 
     * @since 1.0.0
     * @param int $days Number of days to analyze (default: 30)
     * @return array Statistics array
     */
    public function get_otp_statistics($days = 30) {
        $since = gmdate('Y-m-d H:i:s', time() - ($days * 24 * 60 * 60));
        
        $stats = array(
            'total_requests' => 0,
            'successful_verifications' => 0,
            'failed_attempts' => 0,
            'expired_codes' => 0,
            'unique_emails' => 0,
            'top_ips' => array(),
        );
        
        // Total OTP requests in the period
        $stats['total_requests'] = (int) $this->wpdb->get_var(
            $this->wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->otp_table} WHERE created_at >= %s",
                $since
            )
        );
        
        // Unique email addresses
        $stats['unique_emails'] = (int) $this->wpdb->get_var(
            $this->wpdb->prepare(
                "SELECT COUNT(DISTINCT email) FROM {$this->otp_table} WHERE created_at >= %s",
                $since
            )
        );
        
        // Failed attempts (attempts > 0 but not deleted)
        $stats['failed_attempts'] = (int) $this->wpdb->get_var(
            $this->wpdb->prepare(
                "SELECT SUM(attempts) FROM {$this->otp_table} WHERE created_at >= %s AND attempts > 0",
                $since
            )
        );
        
        // Top IP addresses
        $top_ips = $this->wpdb->get_results(
            $this->wpdb->prepare(
                "SELECT ip_address, COUNT(*) as count 
                 FROM {$this->otp_table} 
                 WHERE created_at >= %s AND ip_address != '' 
                 GROUP BY ip_address 
                 ORDER BY count DESC 
                 LIMIT 10",
                $since
            ),
            ARRAY_A
        );
        
        $stats['top_ips'] = $top_ips ?: array();
        
        /**
         * Filter OTP statistics
         * 
         * @since 1.0.0
         * @param array $stats Statistics array
         * @param int $days Number of days analyzed
         */
        return apply_filters('oyic_secure_login_otp_statistics', $stats, $days);
    }

    /**
     * Check rate limiting
     * 
     * Checks if an email address has exceeded rate limiting thresholds.
     * 
     * @since 1.0.0
     * @param string $email User email address
     * @param int $max_attempts Maximum attempts allowed
     * @param int $window_minutes Time window in minutes
     * @return bool True if rate limited, false otherwise
     */
    public function is_rate_limited($email, $max_attempts = 3, $window_minutes = 5) {
        $since = gmdate('Y-m-d H:i:s', time() - ($window_minutes * 60));
        
        $count = (int) $this->wpdb->get_var(
            $this->wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->otp_table} 
                 WHERE email = %s AND created_at >= %s",
                sanitize_email($email),
                $since
            )
        );
        
        return $count >= $max_attempts;
    }

    /**
     * Drop all plugin tables
     * 
     * Completely removes all database tables created by the plugin.
     * This method should only be called during uninstallation.
     * 
     * @since 1.0.0
     * @return bool True on success, false on failure
     */
    public function drop_tables() {
        $result = $this->wpdb->query("DROP TABLE IF EXISTS {$this->otp_table}");
        
        // Remove database version option
        delete_option('oyic_secure_login_db_version');
        
        /**
         * Fires after plugin tables are dropped
         * 
         * @since 1.0.0
         */
        do_action('oyic_secure_login_tables_dropped');
        
        return $result !== false;
    }

    /**
     * Get table status
     * 
     * Returns information about the plugin's database tables.
     * 
     * @since 1.0.0
     * @return array Table status information
     */
    public function get_table_status() {
        $status = array(
            'otp_table_exists' => false,
            'otp_table_size' => 0,
            'database_version' => get_option('oyic_secure_login_db_version', '0.0.0'),
        );
        
        // Check if OTP table exists
        $table_exists = $this->wpdb->get_var(
            $this->wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $this->otp_table
            )
        );
        
        $status['otp_table_exists'] = ($table_exists === $this->otp_table);
        
        if ($status['otp_table_exists']) {
            // Get table size
            $status['otp_table_size'] = (int) $this->wpdb->get_var(
                "SELECT COUNT(*) FROM {$this->otp_table}"
            );
        }
        
        return $status;
    }
}
