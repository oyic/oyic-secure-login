<?php
// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

$login_type = isset($_GET['type']) ? $_GET['type'] : 'standard';
$error = isset($_GET['error']) ? $_GET['error'] : '';
$login_failed = isset($_GET['login']) && $_GET['login'] === 'failed';
$redirect_to = isset($_GET['redirect_to']) ? $_GET['redirect_to'] : admin_url();

// Get plugin options
$options = get_option('secure_login_options', []);
$otp_enabled = isset($options['enable_otp_login']) && $options['enable_otp_login'];

?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login - <?php bloginfo('name'); ?></title>
    <link rel="stylesheet" href="<?php echo includes_url('css/dashicons.min.css'); ?>">
    <style>
        /* OTP Input Container - Inline styles to ensure they load */
        .otp-input-container {
            position: relative;
            display: flex;
            align-items: center;
        }
        
        .otp-input-container input[type="password"],
        .otp-input-container input[type="text"] {
            flex: 1;
            padding-right: 45px;
            font-family: 'Courier New', monospace;
            font-size: 18px;
            letter-spacing: 2px;
            text-align: center;
        }
        
        .otp-toggle-visibility {
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            padding: 8px;
            cursor: pointer;
            color: #666;
            border-radius: 4px;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .otp-toggle-visibility:hover {
            background: #f0f0f0;
            color: #333;
        }
        
        .otp-toggle-visibility .dashicons {
            font-size: 16px;
            width: 16px;
            height: 16px;
        }
        
        #otp-code {
            font-weight: 600;
            background: #f8f9fa;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            padding: 12px 45px 12px 12px;
            transition: border-color 0.2s ease;
        }
        
        #otp-code:focus {
            border-color: #667eea;
            background: white;
            outline: none;
        }
    </style>
    <?php wp_head(); ?>
</head>
<body class="login">
    <div id="loginform-container">
        <div class="login-header">
            <h1><a href="<?php echo esc_url(home_url('/')); ?>"><?php bloginfo('name'); ?></a></h1>
        </div>

        <?php if ($login_failed): ?>
            <div class="login-error">
                <p>Invalid username or password. Please try again.</p>
            </div>
        <?php endif; ?>

        <?php if ($error === 'invalid_otp'): ?>
            <div class="login-error">
                <p>Invalid or expired OTP code. Please try again.</p>
            </div>
        <?php endif; ?>

        <div class="login-tabs">
            <button class="tab-button <?php echo $login_type === 'standard' ? 'active' : ''; ?>" onclick="showTab('standard')">
                Username/Password
            </button>
            <?php if ($otp_enabled): ?>
                <button class="tab-button <?php echo $login_type === 'otp' ? 'active' : ''; ?>" onclick="showTab('otp')">
                    Email OTP
                </button>
            <?php endif; ?>
        </div>

        <!-- Standard Login Form -->
        <div id="standard-login" class="login-form <?php echo $login_type === 'standard' ? 'active' : ''; ?>">
            <form method="post" action="">
                <?php wp_nonce_field('secure_login_nonce'); ?>
                <input type="hidden" name="login_type" value="standard">
                <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>">
                
                <div class="form-group">
                    <label for="username">Username or Email</label>
                    <input type="text" name="username" id="username" required autocomplete="username">
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" name="password" id="password" required autocomplete="current-password">
                </div>
                
                <div class="form-group checkbox-group">
                    <label>
                        <input type="checkbox" name="remember" value="1"> Remember Me
                    </label>
                </div>
                
                <div class="form-group">
                    <button type="submit" class="login-button">Log In</button>
                </div>
            </form>
        </div>

        <?php if ($otp_enabled): ?>
            <!-- OTP Login Form -->
            <div id="otp-login" class="login-form <?php echo $login_type === 'otp' ? 'active' : ''; ?>">
                <!-- DEBUG: Template loaded successfully -->
                <script>console.log('OYIC Secure Login Template Loaded');</script>
                <div id="otp-email-step" class="otp-step active">
                    <form id="otp-email-form">
                        <div class="form-group">
                            <label for="otp-email">Email Address</label>
                            <input type="email" name="email" id="otp-email" required>
                        </div>
                        
                        <div class="form-group">
                            <button type="submit" class="login-button">Send OTP Code</button>
                        </div>
                    </form>
                </div>
                
                <div id="otp-verify-step" class="otp-step">
                    <form method="post" action="" id="otp-verify-form">
                        <?php wp_nonce_field('secure_login_nonce'); ?>
                        <input type="hidden" name="login_type" value="otp_verify">
                        <input type="hidden" name="email" id="verify-email" value="">
                        <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>">
                        
                        <div class="form-group">
                            <label for="otp-code">Enter 6-digit code sent to your email</label>
                            <div class="otp-input-container">
                                <input type="password" name="otp_code" id="otp-code" maxlength="6" pattern="[0-9]{6}" required>
                                <button type="button" class="otp-toggle-visibility" id="otp-toggle-btn">
                                    <span class="dashicons dashicons-visibility"></span>
                                </button>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <button type="submit" class="login-button">Verify & Login</button>
                            <button type="button" class="secondary-button" onclick="backToEmailStep()">Back</button>
                        </div>
                        
                        <div class="otp-info">
                            <p>Code expires in <span id="countdown">10:00</span></p>
                            <p><a href="#" id="resend-otp">Resend code</a></p>
                        </div>
                    </form>
                </div>
            </div>
        <?php endif; ?>

        <div class="login-footer">
            <p><a href="<?php echo esc_url(home_url('/')); ?>">&larr; Back to <?php bloginfo('name'); ?></a></p>
        </div>
    </div>

    <script>
        function showTab(type) {
            // Update URL
            const url = new URL(window.location);
            url.searchParams.set('type', type);
            window.history.replaceState({}, '', url);
            
            // Update tabs
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            document.querySelector(`[onclick="showTab('${type}')"]`).classList.add('active');
            
            // Update forms
            document.querySelectorAll('.login-form').forEach(form => form.classList.remove('active'));
            document.getElementById(`${type}-login`).classList.add('active');
            
            // Focus first input
            setTimeout(() => {
                const activeForm = document.querySelector('.login-form.active');
                const firstInput = activeForm.querySelector('input[type="text"], input[type="email"]');
                if (firstInput) firstInput.focus();
            }, 100);
        }
        
        function backToEmailStep() {
            document.getElementById('otp-email-step').classList.add('active');
            document.getElementById('otp-verify-step').classList.remove('active');
            document.getElementById('otp-email').focus();
        }
        
        // OTP functionality
        <?php if ($otp_enabled): ?>
        jQuery(document).ready(function($) {
            let countdownTimer;
            
            // Handle OTP email form
            $('#otp-email-form').on('submit', function(e) {
                e.preventDefault();
                
                const email = $('#otp-email').val();
                const button = $(this).find('button[type="submit"]');
                
                button.prop('disabled', true).text('Sending...');
                
                $.ajax({
                    url: secureLogin.ajaxUrl,
                    method: 'POST',
                    data: {
                        action: 'send_otp',
                        email: email,
                        nonce: secureLogin.sendOtpNonce
                    },
                    success: function(response) {
                        if (response.success) {
                            $('#verify-email').val(email);
                            $('#otp-email-step').removeClass('active');
                            $('#otp-verify-step').addClass('active');
                            $('#otp-code').focus();
                            startCountdown();
                        } else {
                            alert(response.data || 'Failed to send OTP');
                        }
                    },
                    error: function() {
                        alert('Network error. Please try again.');
                    },
                    complete: function() {
                        button.prop('disabled', false).text('Send OTP Code');
                    }
                });
            });
            
            // Handle resend OTP
            $('#resend-otp').on('click', function(e) {
                e.preventDefault();
                $('#otp-email-form').submit();
            });
            
            // Countdown timer
            function startCountdown() {
                let timeLeft = 600; // 10 minutes in seconds
                
                countdownTimer = setInterval(function() {
                    const minutes = Math.floor(timeLeft / 60);
                    const seconds = timeLeft % 60;
                    
                    $('#countdown').text(
                        minutes.toString().padStart(2, '0') + ':' + 
                        seconds.toString().padStart(2, '0')
                    );
                    
                    if (timeLeft <= 0) {
                        clearInterval(countdownTimer);
                        $('#countdown').text('Expired');
                        $('#otp-code').prop('disabled', true);
                        alert('OTP code has expired. Please request a new one.');
                        backToEmailStep();
                    }
                    
                    timeLeft--;
                }, 1000);
            }
            
            // Auto-format OTP input
            $('#otp-code').on('input', function() {
                this.value = this.value.replace(/[^0-9]/g, '');
            });
            
            // OTP visibility toggle
            $('#otp-toggle-btn').on('click', function() {
                console.log('OTP toggle button clicked'); // Debug log
                const otpInput = $('#otp-code');
                const toggleBtn = $(this);
                const icon = toggleBtn.find('.dashicons');
                
                console.log('Current input type:', otpInput.attr('type')); // Debug log
                
                if (otpInput.attr('type') === 'password') {
                    otpInput.attr('type', 'text');
                    icon.removeClass('dashicons-visibility').addClass('dashicons-hidden');
                    toggleBtn.attr('title', 'Hide OTP code');
                    console.log('Changed to text type'); // Debug log
                } else {
                    otpInput.attr('type', 'password');
                    icon.removeClass('dashicons-hidden').addClass('dashicons-visibility');
                    toggleBtn.attr('title', 'Show OTP code');
                    console.log('Changed to password type'); // Debug log
                }
            });
            
            // OTP functionality is now handled in the main plugin file
        });
        <?php endif; ?>
        
        // Auto-focus first input on page load
        document.addEventListener('DOMContentLoaded', function() {
            const activeForm = document.querySelector('.login-form.active');
            const firstInput = activeForm.querySelector('input[type="text"], input[type="email"]');
            if (firstInput) firstInput.focus();
        });
    </script>

    <?php wp_footer(); ?>
</body>
</html>
