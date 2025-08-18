/**
 * Secure Login JavaScript
 * Handles OTP login functionality and UI interactions
 */

(function($) {
    'use strict';
    
    let countdownTimer;
    let otpAttempts = 0;
    const maxAttempts = 3;
    
    $(document).ready(function() {
        initializeLoginForm();
    });
    
    function initializeLoginForm() {
        // Handle tab switching
        $('.tab-button').on('click', function() {
            const type = $(this).data('type') || $(this).attr('onclick').match(/'([^']+)'/)[1];
            showTab(type);
        });
        
        // Handle OTP email form submission
        $('#otp-email-form').on('submit', handleOtpEmailSubmission);
        
        // Handle OTP verification form
        $('#otp-verify-form').on('submit', handleOtpVerification);
        
        // Handle resend OTP
        $('#resend-otp').on('click', handleResendOtp);
        
        // Auto-format OTP input
        $('#otp-code').on('input', formatOtpInput);
        
        // Handle enter key in OTP input
        $('#otp-code').on('keypress', function(e) {
            if (e.which === 13) {
                $('#otp-verify-form').submit();
            }
        });
        
        // Handle back button
        $('.back-to-email').on('click', backToEmailStep);
        
        // Auto-focus inputs
        autoFocusInputs();
        
        // Initialize countdown if we're already on verify step
        if ($('#otp-verify-step').hasClass('active')) {
            startCountdown();
        }
    }
    
    function showTab(type) {
        // Update URL without page reload
        if (history.replaceState) {
            const url = new URL(window.location);
            url.searchParams.set('type', type);
            history.replaceState({}, '', url);
        }
        
        // Update active tab
        $('.tab-button').removeClass('active');
        $(`.tab-button[onclick*="${type}"]`).addClass('active');
        
        // Update active form
        $('.login-form').removeClass('active');
        $(`#${type}-login`).addClass('active');
        
        // Reset OTP form if switching away from it
        if (type !== 'otp') {
            resetOtpForm();
        }
        
        // Auto-focus
        setTimeout(autoFocusInputs, 100);
    }
    
    function handleOtpEmailSubmission(e) {
        e.preventDefault();
        
        const email = $('#otp-email').val().trim();
        const button = $(this).find('button[type="submit"]');
        
        if (!isValidEmail(email)) {
            showError('Please enter a valid email address.');
            return;
        }
        
        button.prop('disabled', true).text('Sending...');
        hideErrors();
        
        $.ajax({
            url: secureLogin.ajaxUrl,
            method: 'POST',
            data: {
                action: 'send_otp',
                email: email,
                nonce: secureLogin.sendOtpNonce
            },
            timeout: 30000,
            success: function(response) {
                if (response.success) {
                    $('#verify-email').val(email);
                    $('#otp-email-step').removeClass('active');
                    $('#otp-verify-step').addClass('active');
                    $('#otp-code').focus();
                    startCountdown();
                    showSuccess('OTP code sent to your email address.');
                } else {
                    showError(response.data || 'Failed to send OTP. Please try again.');
                }
            },
            error: function(xhr, status, error) {
                if (status === 'timeout') {
                    showError('Request timed out. Please check your internet connection and try again.');
                } else {
                    showError('Network error. Please try again.');
                }
            },
            complete: function() {
                button.prop('disabled', false).text('Send OTP Code');
            }
        });
    }
    
    function handleOtpVerification(e) {
        const otpCode = $('#otp-code').val().trim();
        
        if (!isValidOtpCode(otpCode)) {
            e.preventDefault();
            showError('Please enter a valid 6-digit code.');
            return;
        }
        
        if (otpAttempts >= maxAttempts) {
            e.preventDefault();
            showError('Too many failed attempts. Please request a new code.');
            backToEmailStep();
            return;
        }
        
        otpAttempts++;
        
        // Let the form submit naturally for server-side verification
        const button = $(this).find('button[type="submit"]');
        button.prop('disabled', true).text('Verifying...');
    }
    
    function handleResendOtp(e) {
        e.preventDefault();
        
        if ($(this).hasClass('disabled')) {
            return;
        }
        
        const email = $('#verify-email').val();
        if (!email) {
            backToEmailStep();
            return;
        }
        
        // Reset the form and resend
        $('#otp-email').val(email);
        $('#otp-email-form').submit();
    }
    
    function formatOtpInput() {
        let value = this.value.replace(/[^0-9]/g, '');
        if (value.length > 6) {
            value = value.substring(0, 6);
        }
        this.value = value;
        
        // Auto-submit when 6 digits entered
        if (value.length === 6) {
            setTimeout(() => {
                $('#otp-verify-form').submit();
            }, 500);
        }
    }
    
    function backToEmailStep() {
        $('#otp-verify-step').removeClass('active');
        $('#otp-email-step').addClass('active');
        $('#otp-code').val('');
        $('#otp-email').focus();
        
        if (countdownTimer) {
            clearInterval(countdownTimer);
        }
        
        otpAttempts = 0;
        hideErrors();
    }
    
    function startCountdown() {
        let timeLeft = 600; // 10 minutes in seconds
        
        if (countdownTimer) {
            clearInterval(countdownTimer);
        }
        
        countdownTimer = setInterval(function() {
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            
            const display = minutes.toString().padStart(2, '0') + ':' + 
                          seconds.toString().padStart(2, '0');
            
            $('#countdown').text(display);
            
            // Change color when time is running low
            if (timeLeft <= 60) {
                $('#countdown').addClass('warning');
            }
            
            if (timeLeft <= 0) {
                clearInterval(countdownTimer);
                $('#countdown').text('Expired').addClass('expired');
                $('#otp-code').prop('disabled', true);
                $('#resend-otp').removeClass('disabled');
                showError('OTP code has expired. Please request a new one.');
            }
            
            timeLeft--;
        }, 1000);
        
        // Disable resend for first 30 seconds
        $('#resend-otp').addClass('disabled');
        setTimeout(() => {
            $('#resend-otp').removeClass('disabled');
        }, 30000);
    }
    
    function autoFocusInputs() {
        const activeForm = $('.login-form.active');
        const firstInput = activeForm.find('input[type="text"], input[type="email"], input[type="password"]').first();
        
        if (firstInput.length && firstInput.is(':visible')) {
            firstInput.focus();
        }
    }
    
    function resetOtpForm() {
        $('#otp-email-step').addClass('active');
        $('#otp-verify-step').removeClass('active');
        $('#otp-email').val('');
        $('#otp-code').val('').prop('disabled', false);
        $('#verify-email').val('');
        
        if (countdownTimer) {
            clearInterval(countdownTimer);
        }
        
        otpAttempts = 0;
        hideErrors();
    }
    
    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    
    function isValidOtpCode(code) {
        return /^\d{6}$/.test(code);
    }
    
    function showError(message) {
        hideMessages();
        
        const errorDiv = $('<div class="login-message error">' + escapeHtml(message) + '</div>');
        $('#loginform-container').prepend(errorDiv);
        
        // Auto-hide after 10 seconds
        setTimeout(() => {
            errorDiv.fadeOut();
        }, 10000);
    }
    
    function showSuccess(message) {
        hideMessages();
        
        const successDiv = $('<div class="login-message success">' + escapeHtml(message) + '</div>');
        $('#loginform-container').prepend(successDiv);
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            successDiv.fadeOut();
        }, 5000);
    }
    
    function hideMessages() {
        $('.login-message').remove();
    }
    
    function hideErrors() {
        $('.login-message.error').remove();
    }
    
    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        
        return text.replace(/[&<>"']/g, function(m) {
            return map[m];
        });
    }
    
    // Expose functions globally if needed
    window.secureLoginFunctions = {
        showTab: showTab,
        backToEmailStep: backToEmailStep,
        resetOtpForm: resetOtpForm
    };
    
})(jQuery);
