# Secure Login WordPress Plugin

A comprehensive WordPress security plugin that customizes login URLs, provides backend configuration, and introduces email-based OTP (One-Time Password) authentication.

## Features

### 🔐 Custom Login URL
- Replace default `/wp-login.php` with a custom URL of your choice
- Block unauthorized access to default login endpoints
- Emergency override mechanism for admin access

### 📧 Email OTP Authentication
- Alternative login method using one-time passwords
- 6-digit codes sent via email
- 10-minute expiration with countdown timer
- Rate limiting to prevent abuse

### ⚙️ Admin Configuration
- Easy-to-use settings page in WordPress admin
- Real-time URL preview
- System status monitoring
- Override key management

### 🛡️ Security Features
- Rate limiting for OTP requests
- Secure password hashing for OTP codes
- Nonce verification for all forms
- Session management and cleanup
- Database table for OTP storage

## Installation

1. **Upload the plugin files** to `/wp-content/plugins/secure-login/` directory
2. **Activate the plugin** through the 'Plugins' menu in WordPress
3. **Configure settings** by going to Settings > Secure Login

## Configuration

### Initial Setup

1. Navigate to **Settings > Secure Login** in your WordPress admin
2. Set your **Custom Login Slug** (e.g., "secure-access")
3. **Save your Override Key** in a secure location
4. Test the custom login URL before enabling protection
5. Enable **Custom Login URL** to activate protection
6. Optionally enable **Email OTP Login**

### Settings Overview

| Setting | Description | Default |
|---------|-------------|---------|
| Enable Custom Login URL | Blocks wp-login.php access | Disabled |
| Custom Login Slug | URL slug for custom login | `secure-access` |
| Enable OTP Login | Email-based authentication | Disabled |
| Override Key | Emergency access key | Auto-generated |

## Usage

### Standard Login Flow

1. Visit your custom login URL: `https://yoursite.com/your-slug/`
2. Enter username/email and password
3. Click "Log In"

### OTP Login Flow

1. Visit your custom login URL
2. Click "Email OTP" tab
3. Enter your email address
4. Check email for 6-digit code
5. Enter code to login

### Emergency Access

If locked out, use the override URL:
```
https://yoursite.com/wp-login.php?override=YOUR_OVERRIDE_KEY
```

## Security Considerations

### Rate Limiting
- Maximum 3 OTP requests per email per 5 minutes
- Maximum 3 OTP verification attempts per session
- Automatic lockout with cooldown periods

### Data Protection
- OTP codes are hashed before database storage
- Codes expire after 10 minutes
- Used codes are immediately deleted
- No sensitive data in logs

### Best Practices
1. **Choose a strong, unique login slug**
2. **Keep your override key secure and private**
3. **Test thoroughly before enabling on production**
4. **Monitor failed login attempts**
5. **Regularly update the override key**

## Database Schema

The plugin creates one additional table:

```sql
wp_secure_login_otp (
    id int(11) AUTO_INCREMENT PRIMARY KEY,
    email varchar(255) NOT NULL,
    otp_code varchar(255) NOT NULL,  -- Hashed
    expires_at datetime NOT NULL,
    created_at datetime NOT NULL,
    INDEX(email),
    INDEX(expires_at)
)
```

## File Structure

```
secure-login/
├── secure-login.php          # Main plugin file
├── templates/
│   ├── admin-page.php        # Admin settings page
│   └── login-page.php        # Custom login page
├── assets/
│   ├── secure-login.js       # Frontend JavaScript
│   └── secure-login.css      # Login page styles
└── README.md                 # This file
```

## Hooks and Filters

### Actions
- `secure_login_before_standard_login` - Before standard login processing
- `secure_login_after_standard_login` - After successful standard login
- `secure_login_before_otp_send` - Before OTP email is sent
- `secure_login_after_otp_verify` - After successful OTP verification

### Filters
- `secure_login_otp_email_subject` - Customize OTP email subject
- `secure_login_otp_email_message` - Customize OTP email content
- `secure_login_otp_expiry_time` - Change OTP expiration (default: 600 seconds)
- `secure_login_rate_limit_attempts` - Change rate limit (default: 3)

## Customization Examples

### Custom OTP Email Template

```php
add_filter('secure_login_otp_email_message', function($message, $otp_code, $email) {
    return "
    <h2>Login Code for " . get_bloginfo('name') . "</h2>
    <p>Your secure login code is: <strong>{$otp_code}</strong></p>
    <p>This code expires in 10 minutes.</p>
    <p>If you didn't request this, please ignore this email.</p>
    ";
}, 10, 3);
```

### Extend OTP Expiry Time

```php
add_filter('secure_login_otp_expiry_time', function($seconds) {
    return 1800; // 30 minutes instead of 10
});
```

## Troubleshooting

### Common Issues

**"Page not found" when visiting custom login URL**
- Go to Settings > Permalinks and click "Save Changes" to flush rewrite rules
- Check that your .htaccess file is writable

**OTP emails not being sent**
- Verify WordPress can send emails: `wp_mail()` function
- Check spam folder
- Configure SMTP plugin if needed
- Test with WP Mail SMTP or similar plugin

**Locked out of admin area**
- Use the override URL with your secret key
- Access via FTP and temporarily deactivate the plugin
- Add this to wp-config.php temporarily: `define('SECURE_LOGIN_DISABLE', true);`

**Custom login URL not working**
- Ensure permalinks are enabled (not "Plain")
- Check for conflicting plugins
- Verify .htaccess is writable
- Try flushing rewrite rules

### Debug Mode

Add this to wp-config.php for debugging:

```php
define('SECURE_LOGIN_DEBUG', true);
```

This will log additional information to the WordPress debug log.

## Support

For support, feature requests, or bug reports:

1. Check the troubleshooting section above
2. Review WordPress error logs
3. Test with default theme and no other plugins
4. Provide detailed error messages and steps to reproduce

## Changelog

### Version 1.0.0
- Initial release
- Custom login URL functionality
- Email OTP authentication
- Admin configuration panel
- Rate limiting and security features
- Responsive login page design

## License

This plugin is licensed under the GPL v2 or later.

## Credits

Built with security and user experience in mind. Uses WordPress best practices and follows coding standards.
