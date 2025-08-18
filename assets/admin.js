/**
 * OYIC Secure Login Admin JavaScript
 * Handles admin interface functionality
 */

(function($) {
    'use strict';
    
    $(document).ready(function() {
        initializeAdminInterface();
    });
    
    function initializeAdminInterface() {
        // Handle test email functionality
        $('.test-email-button').on('click', handleTestEmail);
        
        // Handle flush rules functionality
        $('.flush-rules-button').on('click', handleFlushRules);
        
        // Handle generate key functionality
        $('.generate-key-button').on('click', handleGenerateKey);
        
        // Handle settings form validation
        $('form[action="options.php"]').on('submit', validateSettingsForm);
        
        // Handle custom login URL preview
        $('input[name="oyic_secure_login_options[custom_login_slug]"]').on('input', updateLoginUrlPreview);
        
        // Handle override key display
        toggleOverrideKeyVisibility();
        
        // Initialize tooltips
        initializeTooltips();
        
        // Handle tab navigation if present
        initializeTabNavigation();
        
        // Auto-save draft settings
        initializeAutoSave();
    }
    
    function handleTestEmail(e) {
        e.preventDefault();
        
        const button = $(this);
        const originalText = button.text();
        
        button.prop('disabled', true).text(oyicSecureLoginAdmin.strings.testing);
        
        $.ajax({
            url: oyicSecureLoginAdmin.ajaxUrl,
            method: 'POST',
            data: {
                action: 'oyic_test_email',
                nonce: oyicSecureLoginAdmin.nonce
            },
            timeout: 30000,
            success: function(response) {
                if (response.success) {
                    showAdminNotice(response.data, 'success');
                } else {
                    showAdminNotice(response.data || oyicSecureLoginAdmin.strings.testError, 'error');
                }
            },
            error: function(xhr, status, error) {
                if (status === 'timeout') {
                    showAdminNotice('Request timed out. Please check your email configuration.', 'error');
                } else {
                    showAdminNotice('Network error. Please try again.', 'error');
                }
            },
            complete: function() {
                button.prop('disabled', false).text(originalText);
            }
        });
    }
    
    function handleFlushRules(e) {
        e.preventDefault();
        
        if (!confirm(oyicSecureLoginAdmin.strings.confirmFlush)) {
            return;
        }
        
        const button = $(this);
        const originalText = button.text();
        
        button.prop('disabled', true).text('Flushing...');
        
        $.ajax({
            url: oyicSecureLoginAdmin.ajaxUrl,
            method: 'POST',
            data: {
                action: 'oyic_flush_rules',
                nonce: oyicSecureLoginAdmin.nonce
            },
            success: function(response) {
                if (response.success) {
                    showAdminNotice(response.data, 'success');
                    // Reload page after 2 seconds to reflect changes
                    setTimeout(() => {
                        window.location.reload();
                    }, 2000);
                } else {
                    showAdminNotice(response.data || 'Failed to flush rewrite rules.', 'error');
                }
            },
            error: function() {
                showAdminNotice('Network error. Please try again.', 'error');
            },
            complete: function() {
                button.prop('disabled', false).text(originalText);
            }
        });
    }
    
    function handleGenerateKey(e) {
        e.preventDefault();
        
        const button = $(this);
        const keyInput = $('input[name="oyic_secure_login_options[override_key]"]');
        const originalText = button.text();
        
        button.prop('disabled', true).text(oyicSecureLoginAdmin.strings.generating);
        
        $.ajax({
            url: oyicSecureLoginAdmin.ajaxUrl,
            method: 'POST',
            data: {
                action: 'oyic_generate_key',
                nonce: oyicSecureLoginAdmin.nonce
            },
            success: function(response) {
                if (response.success && response.data.key) {
                    keyInput.val(response.data.key);
                    updateOverrideUrlPreview();
                    showAdminNotice('New override key generated successfully.', 'success');
                } else {
                    showAdminNotice('Failed to generate new key.', 'error');
                }
            },
            error: function() {
                showAdminNotice('Network error. Please try again.', 'error');
            },
            complete: function() {
                button.prop('disabled', false).text(originalText);
            }
        });
    }
    
    function validateSettingsForm(e) {
        const customLoginEnabled = $('input[name="oyic_secure_login_options[enable_custom_login]"]').is(':checked');
        const overrideKey = $('input[name="oyic_secure_login_options[override_key]"]').val().trim();
        const customSlug = $('input[name="oyic_secure_login_options[custom_login_slug]"]').val().trim();
        
        let errors = [];
        
        // Validate override key if custom login is enabled
        if (customLoginEnabled && !overrideKey) {
            errors.push('Override key is required when custom login is enabled.');
        }
        
        // Validate custom slug
        if (!customSlug) {
            errors.push('Custom login slug cannot be empty.');
        } else if (!/^[a-z0-9\-_]+$/i.test(customSlug)) {
            errors.push('Custom login slug can only contain letters, numbers, hyphens, and underscores.');
        } else if (customSlug.length < 3) {
            errors.push('Custom login slug must be at least 3 characters long.');
        }
        
        // Validate email settings if OTP is enabled
        const otpEnabled = $('input[name="oyic_secure_login_options[enable_otp_login]"]').is(':checked');
        if (otpEnabled) {
            const fromEmail = $('input[name="oyic_secure_login_options[email_from_address]"]').val().trim();
            if (!fromEmail || !isValidEmail(fromEmail)) {
                errors.push('Valid email address is required when OTP login is enabled.');
            }
        }
        
        if (errors.length > 0) {
            e.preventDefault();
            showAdminNotice(errors.join('<br>'), 'error');
            return false;
        }
        
        // Show warning if enabling custom login
        if (customLoginEnabled) {
            const confirmed = confirm(
                'WARNING: Enabling custom login will block access to wp-login.php. ' +
                'Make sure you have tested your custom login URL and saved your override key. ' +
                'Continue?'
            );
            
            if (!confirmed) {
                e.preventDefault();
                return false;
            }
        }
        
        return true;
    }
    
    function updateLoginUrlPreview() {
        const slug = $(this).val().trim() || 'secure-access';
        const baseUrl = window.location.origin + window.location.pathname.replace('/wp-admin/options-general.php', '');
        const previewUrl = baseUrl + '/' + slug + '/';
        
        $('.login-url-preview').text(previewUrl);
    }
    
    function updateOverrideUrlPreview() {
        const key = $('input[name="oyic_secure_login_options[override_key]"]').val().trim();
        const baseUrl = window.location.origin + window.location.pathname.replace('/wp-admin/options-general.php', '/wp-login.php');
        const overrideUrl = baseUrl + '?override=' + key;
        
        $('.override-url-preview').text(overrideUrl);
    }
    
    function toggleOverrideKeyVisibility() {
        const toggleButton = $('<button type="button" class="button button-small toggle-key-visibility">Show</button>');
        const keyInput = $('input[name="oyic_secure_login_options[override_key]"]');
        
        if (keyInput.length) {
            keyInput.attr('type', 'password');
            keyInput.after(toggleButton);
            
            toggleButton.on('click', function() {
                const isPassword = keyInput.attr('type') === 'password';
                keyInput.attr('type', isPassword ? 'text' : 'password');
                $(this).text(isPassword ? 'Hide' : 'Show');
            });
        }
    }
    
    function initializeTooltips() {
        // Simple tooltip implementation
        $('[data-tooltip]').each(function() {
            const element = $(this);
            const tooltipText = element.data('tooltip');
            
            element.on('mouseenter', function() {
                const tooltip = $('<div class="oyic-tooltip">' + tooltipText + '</div>');
                $('body').append(tooltip);
                
                const offset = element.offset();
                tooltip.css({
                    top: offset.top - tooltip.outerHeight() - 5,
                    left: offset.left + (element.outerWidth() / 2) - (tooltip.outerWidth() / 2)
                });
            });
            
            element.on('mouseleave', function() {
                $('.oyic-tooltip').remove();
            });
        });
    }
    
    function initializeTabNavigation() {
        $('.nav-tab-wrapper .nav-tab').on('click', function(e) {
            e.preventDefault();
            
            const targetTab = $(this).attr('href');
            
            // Update active tab
            $('.nav-tab').removeClass('nav-tab-active');
            $(this).addClass('nav-tab-active');
            
            // Show target content
            $('.tab-content').hide();
            $(targetTab).show();
            
            // Update URL hash
            window.location.hash = targetTab;
        });
        
        // Show tab from URL hash on load
        if (window.location.hash) {
            $('.nav-tab[href="' + window.location.hash + '"]').click();
        }
    }
    
    function initializeAutoSave() {
        let autoSaveTimeout;
        
        $('form[action="options.php"] input, form[action="options.php"] select, form[action="options.php"] textarea').on('change input', function() {
            clearTimeout(autoSaveTimeout);
            
            autoSaveTimeout = setTimeout(() => {
                saveSettingsDraft();
            }, 2000);
        });
    }
    
    function saveSettingsDraft() {
        const formData = $('form[action="options.php"]').serialize();
        
        $.ajax({
            url: oyicSecureLoginAdmin.ajaxUrl,
            method: 'POST',
            data: {
                action: 'oyic_save_draft',
                nonce: oyicSecureLoginAdmin.nonce,
                settings: formData
            },
            success: function(response) {
                if (response.success) {
                    showAutoSaveIndicator();
                }
            }
        });
    }
    
    function showAutoSaveIndicator() {
        const indicator = $('.auto-save-indicator');
        if (indicator.length === 0) {
            $('form[action="options.php"]').prepend('<div class="auto-save-indicator">Draft saved</div>');
        }
        
        $('.auto-save-indicator').show().delay(2000).fadeOut();
    }
    
    function showAdminNotice(message, type = 'info') {
        // Remove existing notices
        $('.oyic-admin-notice').remove();
        
        const noticeClass = `notice notice-${type} is-dismissible oyic-admin-notice`;
        const notice = $(`<div class="${noticeClass}"><p>${message}</p></div>`);
        
        $('.wrap h1').after(notice);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            notice.fadeOut();
        }, 5000);
        
        // Handle dismiss button
        notice.on('click', '.notice-dismiss', function() {
            notice.fadeOut();
        });
    }
    
    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    
    // Global functions for inline onclick handlers
    window.generateOverrideKey = function() {
        $('.generate-key-button').click();
    };
    
    window.testEmail = function() {
        $('.test-email-button').click();
    };
    
    window.flushRules = function() {
        $('.flush-rules-button').click();
    };
    
})(jQuery);
