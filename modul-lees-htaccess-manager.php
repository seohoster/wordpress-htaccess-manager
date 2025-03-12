<?php
/**
 * Plugin Name: Lee's WP .htaccess Manager by Magazinon.ro
 * Description: A lightweight plugin by Lee from Magazinon.ro to manage root and wp-admin .htaccess files with predefined blocks. Free to use, brought to you with love from Lee!
 * Version: 1.9.33
 * Author: Lee @ <a href="https://www.magazinon.ro" target="_blank">Magazinon.ro</a>
 * License: GPL2
 *
 * List of Functions:
 * 1. __construct() - Initializes plugin, defines paths, loads hooks
 * 2. validate_htaccess() - Checks syntax of .htaccess content before saving
 * 3. add_admin_page() - Adds the plugin settings page in WordPress admin
 * 4. load_admin_assets() - Loads CodeMirror and custom scripts/styles
 * 5. handle_form_submission() - Processes form submissions, saves validated .htaccess
 * 6. backup_htaccess() - Creates a backup before modifying .htaccess
 * 7. log_changes() - Logs modifications to .htaccess
 * 8. is_block_present() - Checks if a specific block exists in .htaccess
 * 9. remove_block() - Removes a block from .htaccess before replacing it
 * 10. auto_correct_htaccess() - Automatically fixes common syntax mistakes in .htaccess
 * 11. send_email_notifications() - Sends admin notifications when .htaccess is modified
 * 12. enable_live_tester() - Allows users to test .htaccess rules before applying them
 * 13. check_permissions() - Verifies user permissions and file writability
 * 14. render_admin_page() - Renders the admin page with menu and .htaccess editor
 * 15. ajax_test_htaccess() - Handles AJAX requests for testing .htaccess rules
 * 16. ajax_restore_backup() - Handles AJAX requests to restore a backup
 * 17. get_backups() - Retrieves list of backup files
 * 18. ajax_backup_htaccess() - Handles AJAX requests to backup .htaccess
 * 19. ajax_delete_backup() - Handles AJAX requests to delete a backup
 * 20. set_admin_notice() - Sets a persistent admin notice
 * 21. display_admin_notices() - Displays queued admin notices
 * 22. scan_existing_htaccess() - Scans existing .htaccess for custom rules on activation
 * 23. extract_custom_rules() - Extracts custom rules from .htaccess content
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class WP_HTAccess_Manager {
    private $root_htaccess;
    private $admin_htaccess;
    private $backup_dir;
    private $log_file;
    private $blocks;
    private $block_descriptions;

    public function __construct() {
        $this->root_htaccess = rtrim(ABSPATH, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.htaccess';
        $this->admin_htaccess = rtrim(ABSPATH, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'wp-admin' . DIRECTORY_SEPARATOR . '.htaccess';
        $this->backup_dir = plugin_dir_path(__FILE__) . 'backups' . DIRECTORY_SEPARATOR;
        $this->log_file = plugin_dir_path(__FILE__) . 'htaccess_manager.log';

        $this->blocks = [
            'LSCACHE' => "# BEGIN LSCACHE\n# LiteSpeed Cache Rules\n<IfModule LiteSpeed>\n\tRewriteEngine on\n\tCacheLookup on\n\tRewriteRule .* - [E=Cache-Control:no-autoflush]\n\tRewriteRule litespeed/debug/.*\\.log$ - [F,L]\n\tRewriteRule \\.litespeed_conf\\.dat - [F,L]\n\tRewriteRule wp-content/.*/[^/]*(responsive|css|js|dynamic|loader|fonts)\\.php - [E=cache-control:max-age=3600]\n\tCacheKeyModify -qs:fbclid\n\tCacheKeyModify -qs:gclid\n\tCacheKeyModify -qs:utm*\n\tCacheKeyModify -qs:_ga\n</IfModule>\n# END LSCACHE",
            'BROWSER_CACHE' => "# BEGIN BROWSER_CACHE\n# Browser Caching for Static Assets\n<IfModule mod_expires.c>\n\tExpiresActive on\n\tExpiresByType image/jpeg A31557600\n\tExpiresByType image/png A31557600\n\tExpiresByType image/gif A31557600\n\tExpiresByType image/webp A31557600\n\tExpiresByType text/css A31557600\n\tExpiresByType application/javascript A31557600\n\tExpiresByType application/x-font-woff A31557600\n\tExpiresByType image/x-icon A31557600\n\tExpiresByType text/html A86400\n</IfModule>\n<IfModule mod_headers.c>\n\t<FilesMatch \"\\.(ico|jpe?g|png|gif|woff|css|js)$\">\n\t\tHeader set Cache-Control \"max-age=31557600, public\"\n\t</FilesMatch>\n\t<FilesMatch \"\\.(html|htm)$\">\n\t\tHeader set Cache-Control \"max-age=86400, public\"\n\t</FilesMatch>\n</IfModule>\n# END BROWSER_CACHE",
            'GZIP_COMPRESSION' => "# BEGIN GZIP_COMPRESSION\n# Gzip Compression for Performance\n<IfModule mod_deflate.c>\n\tAddOutputFilterByType DEFLATE text/html text/css text/plain text/xml application/javascript application/json image/svg+xml application/x-font-woff\n\tBrowserMatch ^Mozilla/4 gzip-only-text/html\n\tBrowserMatch ^Mozilla/4\\.0[678] no-gzip\n\tBrowserMatch \\bMSIE !no-gzip !gzip-only-text/html\n</IfModule>\n# END GZIP_COMPRESSION",
            'SECURITY_WP_CONFIG' => "# BEGIN SECURITY_WP_CONFIG\n# Protect wp-config.php\n<Files wp-config.php>\n\tOrder Allow,Deny\n\tDeny from all\n</Files>\n# END SECURITY_WP_CONFIG",
            'SECURITY_XMLRPC' => "# BEGIN SECURITY_XMLRPC\n# Block XML-RPC to Prevent Brute Force\n<Files xmlrpc.php>\n\tOrder Allow,Deny\n\tDeny from all\n</Files>\n# END SECURITY_XMLRPC",
            'SECURITY_NO_INDEX' => "# BEGIN SECURITY_NO_INDEX\n# Disable Directory Listing\nOptions -Indexes\n# END SECURITY_NO_INDEX",
            'SECURITY_HT_FILES' => "# BEGIN SECURITY_HT_FILES\n# Block .ht* Files\n<Files ~ \"^\\.ht\">\n\tOrder Allow,Deny\n\tDeny from all\n</Files>\n# END SECURITY_HT_FILES",
            'REDIRECT_HTTPS' => "# BEGIN REDIRECT_HTTPS\n# Force HTTPS\n<IfModule mod_rewrite.c>\n\tRewriteEngine On\n\tRewriteCond %{HTTPS} off\n\tRewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]\n</IfModule>\n# END REDIRECT_HTTPS",
            'WP_LOGIN_PASSWORD' => "# BEGIN WP_LOGIN_PASSWORD\n# Password Protect wp-login.php\n<Files wp-login.php>\n\tAuthType Basic\n\tAuthName \"Secure Area\"\n\tAuthUserFile \"/path/to/.htpasswd\"\n\tRequire valid-user\n</Files>\n# END WP_LOGIN_PASSWORD",
            'CORS_ORIGIN' => "# BEGIN CORS_ORIGIN\n# Fix CORS for Fonts and Assets\n<IfModule mod_headers.c>\n\t<FilesMatch \"\\.(ttf|otf|woff|woff2|css|js)$\">\n\t\tHeader set Access-Control-Allow-Origin \"*\"\n\t</FilesMatch>\n</IfModule>\n# END CORS_ORIGIN",
            'PHP_TWEAKS' => "# BEGIN PHP_TWEAKS\n# PHP Configuration Tweaks\nphp_value max_input_vars 100000\nphp_value suhosin.request.max_vars 2048\nphp_value suhosin.request.max_value_length 1000000\nphp_value suhosin.post.max_vars 2048\nphp_value suhosin.post.max_value_length 1000000\nphp_value max_execution_time 30000\n# END PHP_TWEAKS",
            'MOD_SECURITY' => "# BEGIN MOD_SECURITY\n# ModSecurity Filtering for Security\n<IfModule mod_security.c>\n\tSecFilterEngine On\n\tSecAuditEngine RelevantOnly\n\tSecFilterCheckURLEncoding On\n\tSecFilterCheckUnicodeEncoding On\n\tSecFilterForceByteRange 1 255\n\tSecFilterScanPOST On\n\tSecFilterDefaultAction \"deny,log,status:406\"\n\tSecFilter \"select.+from\"\n\tSecFilter \"drop[[:space:]]table\"\n\tSecFilter \"insert[[:space:]]into\"\n\tSecFilter \"<script\"\n\tSecFilter \"\\.\\./\"\n\tSecFilterSelective REQUEST_METHOD \"^POST$\" chain\n\tSecFilterSelective HTTP_Content-Length \"^$\"\n</IfModule>\n# END MOD_SECURITY",
            'ANTI_XSS' => "# BEGIN ANTI_XSS\n# Anti-XSS and SQL Injection Protection\n<IfModule mod_rewrite.c>\n\tRewriteEngine On\n\tRewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3E) [NC,OR]\n\tRewriteCond %{QUERY_STRING} GLOBALS= [NC,OR]\n\tRewriteCond %{QUERY_STRING} _REQUEST= [NC,OR]\n\tRewriteCond %{QUERY_STRING} union|select|insert|drop|update|md5|benchmark [NC]\n\tRewriteRule .* - [F,L]\n</IfModule>\n# END ANTI_XSS",
            'HOTLINK_PROTECTION' => "# BEGIN HOTLINK_PROTECTION\n# Prevent Hotlinking (bypassed on localhost)\n<IfModule mod_rewrite.c>\n\tRewriteEngine On\n\tRewriteCond %{HTTP_HOST} !^(localhost|127\\.0\\.0\\.1)$ [NC]\n\tRewriteCond %{HTTP_REFERER} !^$\n\tRewriteCond %{HTTP_REFERER} !^https?://(www\\.)?{{HOME_URL}}/ [NC]\n\tRewriteRule \\.(jpg|jpeg|png|gif|webp|pdf)$ - [F,L]\n</IfModule>\n# END HOTLINK_PROTECTION",
            'BLOCK_BOTS' => "# BEGIN BLOCK_BOTS\n# Block AI Scraping Bots\n<IfModule mod_rewrite.c>\n\tRewriteEngine On\n\tRewriteCond %{HTTP_USER_AGENT} (CCBot|ChatGPT-User|GPTBot|Google-Extended|Google-CloudVertexBot|Applebot-Extended|anthropic-ai|ClaudeBot|Omgilibot|Omgili|Diffbot|AI2Bot|Bytespider|PanguBot|ImagesiftBot|PerplexityBot|cohere-ai|cohere-training-data-crawler|Timpibot|YouBot) [NC]\n\tRewriteRule .* - [F,L]\n</IfModule>\n# END BLOCK_BOTS",
            'LIMIT_UPLOAD_SIZE' => "# BEGIN LIMIT_UPLOAD_SIZE\n# Limit Upload Size to 10MB\nLimitRequestBody 10485760\n# END LIMIT_UPLOAD_SIZE",
            'DISABLE_PHP_EXECUTION' => "# BEGIN DISABLE_PHP_EXECUTION\n# Disable PHP in Uploads\n<IfModule mod_rewrite.c>\n\tRewriteEngine On\n\tRewriteRule ^wp-content/uploads/.*\\.php$ - [F,L]\n</IfModule>\n# END DISABLE_PHP_EXECUTION",
            'FORCE_DOWNLOAD' => "# BEGIN FORCE_DOWNLOAD\n# Force Download for Files\n<FilesMatch \"\\.(pdf|zip|rar)$\">\n\tForceType application/octet-stream\n\tHeader set Content-Disposition attachment\n</FilesMatch>\n# END FORCE_DOWNLOAD",
            'REDIRECT_WWW' => "# BEGIN REDIRECT_WWW\n# Force non-www\n<IfModule mod_rewrite.c>\n\tRewriteEngine On\n\tRewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\n\tRewriteRule ^ https://%1%{REQUEST_URI} [R=301,L]\n</IfModule>\n# END REDIRECT_WWW",
            'HSTS_HEADER' => "# BEGIN HSTS_HEADER\n# Enable HSTS\n<IfModule mod_headers.c>\n\tHeader set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" env=HTTPS\n</IfModule>\n# END HSTS_HEADER", // Updated with preload
            // New blocks
            'SECURITY_HEADERS' => "# BEGIN SECURITY_HEADERS\n# Additional Security Headers\n<IfModule mod_headers.c>\n\tHeader set X-XSS-Protection \"1; mode=block\"\n\tHeader set X-Content-Type-Options \"nosniff\"\n\tHeader set X-Permitted-Cross-Domain-Policies \"none\"\n\tHeader set X-Frame-Options \"SAMEORIGIN\"\n\tHeader set Referrer-Policy \"no-referrer-when-downgrade\"\n</IfModule>\n# END SECURITY_HEADERS",
            'DISABLE_USER_ENUM' => "# BEGIN DISABLE_USER_ENUM\n# Disable User Enumeration\n<IfModule mod_rewrite.c>\n\tRewriteEngine On\n\tRewriteBase /\n\tRewriteCond %{QUERY_STRING} author=d\n\tRewriteRule ^.*$ - [F,L]\n</IfModule>\n# END DISABLE_USER_ENUM",
            'DISABLE_PHP_INCLUDES' => "# BEGIN DISABLE_PHP_INCLUDES\n# Disable PHP in wp-includes\n<IfModule mod_rewrite.c>\n\tRewriteEngine On\n\tRewriteRule ^wp-includes/.*\\.php$ - [F,L]\n</IfModule>\n# END DISABLE_PHP_INCLUDES",
            'DISABLE_PHP_WPCONTENT' => "# BEGIN DISABLE_PHP_WPCONTENT\n# Disable PHP in wp-content (except plugins/themes)\n<IfModule mod_rewrite.c>\n\tRewriteEngine On\n\tRewriteRule ^wp-content/(?!plugins/|themes/).*\\.php$ - [F,L]\n</IfModule>\n# END DISABLE_PHP_WPCONTENT"    
        ];

        $this->block_descriptions = [
            'LSCACHE' => 'Optimizes caching for LiteSpeed servers.',
            'BROWSER_CACHE' => 'Enables browser caching for static assets like images and scripts.',
            'GZIP_COMPRESSION' => 'Compresses content to speed up page loads.',
            'SECURITY_WP_CONFIG' => 'Blocks access to wp-config.php.',
            'SECURITY_XMLRPC' => 'Disables XML-RPC to prevent brute-force attacks.',
            'SECURITY_NO_INDEX' => 'Prevents directory listing.',
            'SECURITY_HT_FILES' => 'Blocks access to .htaccess and similar files.',
            'REDIRECT_HTTPS' => 'Forces all traffic to HTTPS.',
            'WP_LOGIN_PASSWORD' => 'Adds password protection to wp-login.php (requires .htpasswd).',
            'CORS_ORIGIN' => 'Fixes CORS issues for fonts and assets.',
            'PHP_TWEAKS' => 'Adjusts PHP settings for better performance.',
            'MOD_SECURITY' => 'Enables ModSecurity filters for extra protection.',
            'ANTI_XSS' => 'Blocks XSS and SQL injection attempts in query strings.',
            'HOTLINK_PROTECTION' => 'Prevents other sites from hotlinking your files (disabled on localhost).',
            'BLOCK_BOTS' => 'Blocks AI scraping bots like GPTBot and ClaudeBot.',
            'LIMIT_UPLOAD_SIZE' => 'Caps upload size at 10MB to prevent abuse.',
            'DISABLE_PHP_EXECUTION' => 'Blocks PHP execution in wp-content/uploads.',
            'FORCE_DOWNLOAD' => 'Forces downloads for PDFs, ZIPs, and RARs.',
            'REDIRECT_WWW' => 'Forces non-www URLs (toggleable to www).',
            'HSTS_HEADER' => 'Enforces HTTPS with HSTS for a year, with preload support.',
            'SECURITY_HEADERS' => 'Adds security headers to protect against common web vulnerabilities.',
            'DISABLE_USER_ENUM' => 'Prevents user enumeration via author query strings.',
            'DISABLE_PHP_INCLUDES' => 'Blocks PHP execution in wp-includes directory.',
            'DISABLE_PHP_WPCONTENT' => 'Blocks PHP execution in wp-content, except in plugins and themes.'
        ];

        add_action('admin_menu', [$this, 'add_admin_page']);
        add_action('admin_init', [$this, 'handle_form_submission']);
        add_action('admin_enqueue_scripts', [$this, 'load_admin_assets']);
        add_action('wp_ajax_test_htaccess', [$this, 'ajax_test_htaccess']);
        add_action('wp_ajax_restore_backup', [$this, 'ajax_restore_backup']);
        add_action('wp_ajax_backup_htaccess', [$this, 'ajax_backup_htaccess']);
        add_action('wp_ajax_delete_backup', [$this, 'ajax_delete_backup']);
        add_action('admin_notices', [$this, 'display_admin_notices']); // New hook
        if (is_admin()) {
            $this->check_permissions();
        }
    }

    private function check_permissions() {
        if (!current_user_can('manage_options')) {
            add_action('admin_notices', function() {
                echo '<div class="notice notice-error"><p>You do not have sufficient permissions to access this page.</p></div>';
            });
            return false;
        }

        if (!is_writable($this->root_htaccess) || !is_writable($this->admin_htaccess)) {
            add_action('admin_notices', function() {
                echo '<div class="notice notice-error"><p>Unable to write to one or both .htaccess files. Check permissions.</p></div>';
            });
            return false;
        }
        return true;
    }

    public function validate_htaccess($content) {
        $stack = [];
        $lines = explode("\n", $content);

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || $line[0] === '#') {
                continue; // Skip empty lines and comments
            }

            if (preg_match('/^<Directory\s+[^>]+>$/i', $line)) {
                return false; // <Directory> not allowed in .htaccess
            }

            if (preg_match('/^<IfModule\s+[^>]+>$/i', $line)) {
                array_push($stack, 'IfModule');
            } elseif (preg_match('/^<Files\s+[^>]+>$/i', $line)) {
                array_push($stack, 'Files');
            } elseif (preg_match('/^<\/IfModule>$/i', $line)) {
                if (empty($stack) || array_pop($stack) !== 'IfModule') {
                    return false;
                }
            } elseif (preg_match('/^<\/Files>$/i', $line)) {
                if (empty($stack) || array_pop($stack) !== 'Files') {
                    return false;
                }
            } elseif ((substr_count($line, '"') % 2 !== 0) || (substr_count($line, "'") % 2 !== 0)) {
                return false;
            }
        }
        return empty($stack); // Check tag balance
    }

    public function add_admin_page() {
        add_menu_page(
            "Lee's .htaccess Manager",
            "Lee's .htaccess Manager",
            'manage_options',
            'htaccess-manager',
            [$this, 'render_admin_page'],
            'dashicons-admin-generic'
        );
        add_submenu_page(
            'htaccess-manager',
            'Edit .htaccess',
            'Edit .htaccess',
            'manage_options',
            'htaccess-manager',
            [$this, 'render_admin_page']
        );
    }

    public function load_admin_assets($hook) {
        if ($hook !== 'toplevel_page_htaccess-manager') {
            return;
        }
        wp_enqueue_script('jquery');
        wp_enqueue_script('codemirror-js', 'https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/codemirror.min.js', ['jquery'], '5.65.5', true);
        wp_enqueue_script('codemirror-mode', 'https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/mode/apache/apache.min.js', ['codemirror-js'], '5.65.5', true);
        wp_enqueue_style('codemirror-css', 'https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/codemirror.min.css', [], '5.65.5');
        wp_enqueue_style('htaccess-manager-css', plugin_dir_url(__FILE__) . 'assets/css/htaccess-manager.css', [], '1.0');
        $current_file = isset($_GET['file']) && $_GET['file'] === 'admin' ? 'admin' : 'root';
        $file_path = $current_file === 'admin' ? $this->admin_htaccess : $this->root_htaccess;
        $current_content = file_exists($file_path) ? file_get_contents($file_path) : '';
        wp_localize_script('codemirror-js', 'htaccessData', [
            'blocks' => $this->blocks,
            'descriptions' => $this->block_descriptions,
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('htaccess_test_nonce'),
            'restore_nonce' => wp_create_nonce('htaccess_restore_nonce'),
            'backup_nonce' => wp_create_nonce('htaccess_backup_nonce'),
            'delete_nonce' => wp_create_nonce('htaccess_delete_nonce'), // New nonce
            'home_url' => home_url(),
            'current_content' => $current_content
        ]);
    }

    public function handle_form_submission() {
        if (!isset($_POST['save_htaccess'])) {
            return;
        }
    
        if (!check_admin_referer('htaccess_manager_save', 'htaccess_nonce')) {
            return;
        }
    
        $file_to_edit = $_POST['htaccess_file'] ?? 'root';
        $content = stripslashes($_POST['htaccess_content'] ?? '');
    
        $this->backup_htaccess($file_to_edit);
    
        if ($this->validate_htaccess($content)) {
            $target_file = ($file_to_edit === 'admin') ? $this->admin_htaccess : $this->root_htaccess;
            $original_content = file_exists($target_file) ? file_get_contents($target_file) : '';
            if (file_put_contents($target_file, $content) !== false) {
                $this->log_changes($original_content, $content);
                $this->send_email_notifications("Updated $file_to_edit .htaccess");
                $this->set_admin_notice(".htaccess file updated successfully!", 'success');
    
                // Preserve custom rules in option if still present
                if (strpos($content, '# BEGIN CUSTOM_RULES') !== false) {
                    $custom_rules = $this->extract_custom_rules($content);
                    update_option("htaccess_manager_custom_rules_{$file_to_edit}", $custom_rules);
                } else {
                    delete_option("htaccess_manager_custom_rules_{$file_to_edit}");
                }
            } else {
                $this->set_admin_notice("Error: Failed to write to .htaccess file.", 'error');
            }
        } else {
            $this->set_admin_notice("Error: Invalid .htaccess syntax detected! Changes were not applied.", 'error');
        }
    }

    public function render_admin_page() {
        $current_file = isset($_GET['file']) && $_GET['file'] === 'admin' ? 'admin' : 'root';
        $file_path = $current_file === 'admin' ? $this->admin_htaccess : $this->root_htaccess;
        $content = file_exists($file_path) ? file_get_contents($file_path) : '';
        $backups = $this->get_backups($current_file);
    
        // Append custom rules if not already present
        if ($custom_rules = get_option("htaccess_manager_custom_rules_{$current_file}")) {
            if (strpos($content, '# BEGIN CUSTOM_RULES') === false) {
                $content .= "\n# BEGIN CUSTOM_RULES\n# Preserved custom rules from your original .htaccess\n" . $custom_rules . "\n# END CUSTOM_RULES";
            }
        }
    
        ?>
        <div class="wrap">
            <h1>Lee's WP .htaccess Manager by Magazinon.ro</h1>
            <p style="font-size: 14px;">Crafted with care by Lee - Check out more awesome tools at <a href="https://www.magazinon.ro" target="_blank">Magazinon.ro</a>!</p>
            <div class="htaccess-menu">
                <a href="<?php echo admin_url('admin.php?page=htaccess-manager&file=root'); ?>" class="button <?php echo $current_file === 'root' ? 'button-primary' : ''; ?>">Root .htaccess</a>
                <a href="<?php echo admin_url('admin.php?page=htaccess-manager&file=admin'); ?>" class="button <?php echo $current_file === 'admin' ? 'button-primary' : ''; ?>">wp-admin .htaccess</a>
            </div>
            <form method="post" action="">
                <?php wp_nonce_field('htaccess_manager_save', 'htaccess_nonce'); ?>
                <input type="hidden" name="htaccess_file" value="<?php echo esc_attr($current_file); ?>">
                <h2>Editing: <?php echo $current_file === 'root' ? 'Root' : 'wp-admin'; ?> .htaccess</h2>
                <textarea name="htaccess_content" id="htaccess-editor" rows="15" cols="80"><?php echo esc_textarea($content); ?></textarea>
                <h2>Predefined Blocks (hover button for description)</h2>
                <div id="predefined-blocks">
                    <?php foreach ($this->blocks as $key => $block) : ?>
                        <button type="button" class="block-button" data-block="<?php echo esc_attr($key); ?>" title="<?php echo esc_attr($this->block_descriptions[$key]); ?>"><?php echo esc_html($key); ?></button>
                    <?php endforeach; ?>
                </div>
                <p>
                    <button type="button" id="test-htaccess" class="button">Test Rules</button>
                    <button type="button" id="add-all-rules" class="button">Add All Rules</button>
                    <button type="button" id="delete-all-rules" class="button">Delete All</button>
                </p>
                <p><input type="submit" name="save_htaccess" class="button button-primary" value="Save Changes"></p>
            </form>
            <h2>Backups</h2>
            <div id="backup-list">
                <?php if (empty($backups)) : ?>
                    <p>No backups available.</p>
                <?php else : ?>
                    <ul>
                        <?php foreach ($backups as $backup) : ?>
                            <li>
                                <?php echo esc_html(basename($backup)); ?>
                                <button type="button" class="restore-backup" data-file="<?php echo esc_attr(basename($backup)); ?>" data-target="<?php echo esc_attr($current_file); ?>">Restore</button>
                                <button type="button" class="delete-backup" data-file="<?php echo esc_attr(basename($backup)); ?>" data-target="<?php echo esc_attr($current_file); ?>">Delete</button>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
            <p><strong>Logs:</strong> Saved at <?php echo esc_html($this->log_file); ?></p>
            <p><strong>Backups:</strong> Saved in <?php echo esc_html($this->backup_dir); ?></p>
            <hr>
            <p style="text-align: center; font-size: 12px;">Enjoying this free plugin? Support Lee by visiting <a href="https://www.magazinon.ro" target="_blank">Magazinon.ro</a> for more cool stuff!</p>
        </div>
        <script>
            jQuery(document).ready(function($) {
                var editor = CodeMirror.fromTextArea(document.getElementById('htaccess-editor'), {
                    lineNumbers: true,
                    mode: 'apache',
                    theme: 'default'
                });
    
                // Restore content from transient if available
                <?php
                if ($transient_content = get_transient('htaccess_manager_test_content')) {
                    echo "editor.setValue(" . json_encode($transient_content) . ");";
                    delete_transient('htaccess_manager_test_content'); // Clear after use
                }
                ?>
    
                // Function to update button states
                function updateButtonStates() {
                    var content = editor.getValue().trim();
                    $('.block-button').each(function() {
                        var blockKey = $(this).data('block');
                        var startMarker = '# BEGIN ' + blockKey;
                        var isPresent = content.indexOf(startMarker) !== -1;
                        $(this).removeClass('block-added block-not-added')
                               .addClass(isPresent ? 'block-added' : 'block-not-added');
                    });
                }
    
                // Initial button state update
                updateButtonStates();
    
                // Update states on content change and auto-backup
                editor.on('change', function() {
                    updateButtonStates();
                    var content = editor.getValue();
                    $.ajax({
                        url: htaccessData.ajax_url,
                        method: 'POST',
                        data: {
                            action: 'backup_htaccess',
                            file: '<?php echo esc_js($current_file); ?>',
                            content: content,
                            nonce: htaccessData.backup_nonce
                        },
                        success: function(response) {
                            if (!response.success) {
                                console.log('Backup failed: ' + response.message);
                            }
                        },
                        error: function(xhr, status, error) {
                            console.log('Backup AJAX error: ' + error);
                        }
                    });
                });
    
                // Toggle block on button click
                $('.block-button').on('click', function() {
                    var blockKey = $(this).data('block');
                    var blockContent = htaccessData.blocks[blockKey];
                    blockContent = blockContent.replace('{{HOME_URL}}', htaccessData.home_url.replace(/^https?:\/\//, ''));
                    var currentContent = editor.getValue().trim();
                    var startMarker = '# BEGIN ' + blockKey;
                    var endMarker = '# END ' + blockKey;
    
                    var startIdx = currentContent.indexOf(startMarker);
                    if (startIdx !== -1) {
                        var endIdx = currentContent.indexOf(endMarker, startIdx);
                        if (endIdx !== -1) {
                            endIdx += endMarker.length;
                            currentContent = currentContent.substring(0, startIdx).trim() + '\n' + currentContent.substring(endIdx).trim();
                            editor.setValue(currentContent.trim());
                        }
                    } else {
                        var wpStart = currentContent.indexOf('# BEGIN WordPress');
                        var newContent = '';
                        if (wpStart === -1) {
                            newContent = currentContent ? blockContent + '\n' + currentContent : blockContent;
                        } else {
                            newContent = currentContent.substring(0, wpStart).trim() + (currentContent.substring(0, wpStart) ? '\n' : '') + blockContent + '\n' + currentContent.substring(wpStart).trim();
                        }
                        editor.setValue(newContent.trim());
                    }
                    updateButtonStates();
                });
    
                // Add All Rules button handler
                $('#add-all-rules').on('click', function() {
                    var currentContent = editor.getValue().trim();
                    var wpBlock = '';
                    var newContent = '# Note: WP_LOGIN_PASSWORD is excluded by default. Use it only for extreme password protection needs (requires .htpasswd setup).\n';
    
                    var wpStart = currentContent.indexOf('# BEGIN WordPress');
                    if (wpStart !== -1) {
                        var wpEnd = currentContent.indexOf('# END WordPress', wpStart);
                        if (wpEnd !== -1) {
                            wpEnd += '# END WordPress'.length;
                            wpBlock = currentContent.substring(wpStart, wpEnd).trim();
                            currentContent = currentContent.substring(0, wpStart).trim() + currentContent.substring(wpEnd).trim();
                        }
                    }
    
                    for (var blockKey in htaccessData.blocks) {
                        if (blockKey !== 'WP_LOGIN_PASSWORD') {
                            var blockContent = htaccessData.blocks[blockKey];
                            blockContent = blockContent.replace('{{HOME_URL}}', htaccessData.home_url.replace(/^https?:\/\//, ''));
                            var startMarker = '# BEGIN ' + blockKey;
                            var endMarker = '# END ' + blockKey;
    
                            var startIdx = currentContent.indexOf(startMarker);
                            if (startIdx !== -1) {
                                var endIdx = currentContent.indexOf(endMarker, startIdx);
                                if (endIdx !== -1) {
                                    endIdx += endMarker.length;
                                    currentContent = currentContent.substring(0, startIdx).trim() + currentContent.substring(endIdx).trim();
                                }
                            }
    
                            newContent += blockContent + '\n';
                        }
                    }
    
                    if (wpBlock) {
                        newContent += wpBlock;
                    }
    
                    editor.setValue(newContent.trim());
                    updateButtonStates();
                });
    
                // Delete All Rules button handler
                $('#delete-all-rules').on('click', function() {
                    if (!confirm('Are you sure you want to delete all custom rules? This will keep WordPress, LiteSpeed Cache, and Wordfence WAF rules if present.')) {
                        return;
                    }
    
                    var currentContent = editor.getValue().trim();
                    var newContent = '';
                    var wpBlock = '';
                    var lscacheBlock = '';
                    var wordfenceBlock = '';
    
                    var wpStart = currentContent.indexOf('# BEGIN WordPress');
                    if (wpStart !== -1) {
                        var wpEnd = currentContent.indexOf('# END WordPress', wpStart);
                        if (wpEnd !== -1) {
                            wpEnd += '# END WordPress'.length;
                            wpBlock = currentContent.substring(wpStart, wpEnd).trim();
                        }
                    }
    
                    var lscacheStart = currentContent.indexOf('# BEGIN LSCACHE');
                    if (lscacheStart !== -1) {
                        var lscacheEnd = currentContent.indexOf('# END LSCACHE', lscacheStart);
                        if (lscacheEnd !== -1) {
                            lscacheEnd += '# END LSCACHE'.length;
                            lscacheBlock = currentContent.substring(lscacheStart, lscacheEnd).trim();
                        }
                    }
    
                    var wfStart = currentContent.indexOf('# BEGIN Wordfence WAF');
                    if (wfStart !== -1) {
                        var wfEnd = currentContent.indexOf('# END Wordfence WAF', wfStart);
                        if (wfEnd !== -1) {
                            wfEnd += '# END Wordfence WAF'.length;
                            wordfenceBlock = currentContent.substring(wfStart, wfEnd).trim();
                        }
                    }
    
                    if (lscacheBlock) {
                        newContent += lscacheBlock + '\n';
                    }
                    if (wordfenceBlock) {
                        newContent += wordfenceBlock + '\n';
                    }
                    if (wpBlock) {
                        newContent += wpBlock;
                    }
    
                    editor.setValue(newContent.trim());
                    updateButtonStates();
                });
    
                // Test Rules button handler
                $('#test-htaccess').on('click', function() {
                    var content = editor.getValue();
                    $.ajax({
                        url: htaccessData.ajax_url,
                        method: 'POST',
                        data: {
                            action: 'test_htaccess',
                            content: content,
                            file: '<?php echo esc_js($current_file); ?>',
                            nonce: htaccessData.nonce,
                            editor_content: content // Send editor content
                        },
                        success: function(response) {
                            if (response.success) {
                                location.reload(); // Refresh to show notice and restore content
                            } else {
                                location.reload(); // Refresh to show error notice and restore content
                            }
                        },
                        error: function(xhr, status, error) {
                            console.log('Test AJAX error: ' + error);
                            location.reload(); // Refresh to show generic error notice
                        }
                    });
                });
    
                // Restore Backup button handler
                $('.restore-backup').on('click', function() {
                    var backupFile = $(this).data('file');
                    var targetFile = $(this).data('target');
                    if (confirm('Restore ' + backupFile + ' to ' + targetFile + ' .htaccess?')) {
                        $.ajax({
                            url: htaccessData.ajax_url,
                            method: 'POST',
                            data: {
                                action: 'restore_backup',
                                backup: backupFile,
                                file: targetFile,
                                nonce: htaccessData.restore_nonce
                            },
                            success: function(response) {
                                if (response.success) {
                                    editor.setValue(response.content || '');
                                    location.reload(); // Refresh to show notice
                                } else {
                                    location.reload(); // Refresh to show error notice
                                }
                            },
                            error: function(xhr, status, error) {
                                console.log('Restore AJAX error: ' + error);
                                location.reload(); // Refresh to show generic error notice
                            }
                        });
                    }
                });
    
                // Delete Backup button handler
                $('.delete-backup').on('click', function() {
                    var backupFile = $(this).data('file');
                    var targetFile = $(this).data('target');
                    if (confirm('Delete backup ' + backupFile + '? This action cannot be undone.')) {
                        $.ajax({
                            url: htaccessData.ajax_url,
                            method: 'POST',
                            data: {
                                action: 'delete_backup',
                                backup: backupFile,
                                file: targetFile,
                                nonce: htaccessData.delete_nonce
                            },
                            success: function(response) {
                                if (response.success) {
                                    location.reload(); // Refresh to show notice and update list
                                } else {
                                    location.reload(); // Refresh to show error notice
                                }
                            },
                            error: function(xhr, status, error) {
                                console.log('Delete AJAX error: ' + error);
                                location.reload(); // Refresh to show generic error notice
                            }
                        });
                    }
                });
            });
        </script>
        <?php
    }

    public function ajax_test_htaccess() {
        if (!check_ajax_referer('htaccess_test_nonce', 'nonce', false)) {
            $this->set_admin_notice('Nonce verification failed during .htaccess test.', 'error');
            wp_send_json(['success' => false]);
            return;
        }
    
        $content = stripslashes($_POST['content'] ?? '');
        $editor_content = stripslashes($_POST['editor_content'] ?? ''); // Get editor content
        $file_to_test = $_POST['file'] === 'admin' ? $this->admin_htaccess : $this->root_htaccess;
    
        // Store editor content in a transient for restoration
        set_transient('htaccess_manager_test_content', $editor_content, 30);
    
        if (empty(trim($content))) {
            $this->set_admin_notice('Empty .htaccess tested (HTTP 200 assumed).', 'success');
            wp_send_json(['success' => true]);
            return;
        }
    
        $result = $this->enable_live_tester($content, $file_to_test);
        if ($result['success']) {
            $this->set_admin_notice($result['message'], 'success');
        } else {
            $this->set_admin_notice($result['message'], 'error');
        }
        wp_send_json(['success' => $result['success']]);
    }

    public function ajax_restore_backup() {
        if (!check_ajax_referer('htaccess_restore_nonce', 'nonce', false)) {
            $this->set_admin_notice('Nonce verification failed during backup restore.', 'error');
            wp_send_json(['success' => false]);
            return;
        }
    
        $backup_file = sanitize_file_name($_POST['backup'] ?? '');
        $file_to_restore = $_POST['file'] === 'admin' ? $this->admin_htaccess : $this->root_htaccess;
    
        $backup_path = $this->backup_dir . $backup_file;
        if (!file_exists($backup_path)) {
            $this->set_admin_notice('Backup file not found.', 'error');
            wp_send_json(['success' => false]);
            return;
        }
    
        $content = file_get_contents($backup_path);
        if (file_put_contents($file_to_restore, $content) !== false) {
            $this->log_changes('', $content);
            $this->send_email_notifications("Restored $backup_file to " . ($file_to_restore === $this->admin_htaccess ? 'wp-admin' : 'root') . " .htaccess");
            $this->set_admin_notice("Backup $backup_file restored successfully.", 'success');
            wp_send_json(['success' => true, 'content' => $content]);
        } else {
            $this->set_admin_notice('Failed to restore backup.', 'error');
            wp_send_json(['success' => false]);
        }
    }

    private function backup_htaccess($file_type, $suffix = null) {
        if (!file_exists($this->backup_dir)) {
            wp_mkdir_p($this->backup_dir);
        }
        $source_file = $file_type === 'admin' ? $this->admin_htaccess : $this->root_htaccess;
        $backup_suffix = $suffix ?: 'backup-' . date('Y-m-d_H-i-s');
        $backup_filename = $this->backup_dir . $file_type . '-htaccess-' . $backup_suffix . '.bak';
        if (file_exists($source_file)) {
            copy($source_file, $backup_filename);
        }
    }

    private function backup_htaccess($file_type) {
        if (!file_exists($this->backup_dir)) {
            wp_mkdir_p($this->backup_dir);
        }
        $source_file = $file_type === 'admin' ? $this->admin_htaccess : $this->root_htaccess;
        $backup_filename = $this->backup_dir . $file_type . '-htaccess-backup-' . date('Y-m-d_H-i-s') . '.bak';
        if (file_exists($source_file)) {
            copy($source_file, $backup_filename);
        }
    }

    private function log_changes($old_content, $new_content) {
        if (!file_exists(dirname($this->log_file))) {
            wp_mkdir_p(dirname($this->log_file));
        }
        $log_entry = sprintf(
            "[%s] User: %s (IP: %s) changed .htaccess\nNew Content:\n%s\n",
            date('Y-m-d H:i:s'),
            wp_get_current_user()->user_login,
            $_SERVER['REMOTE_ADDR'],
            $new_content
        );
        file_put_contents($this->log_file, $log_entry, FILE_APPEND | LOCK_EX);
    }

    public function is_block_present($content, $block_name) {
        return strpos($content, "# BEGIN $block_name") !== false;
    }

    public function remove_block($content, $block_name) {
        $startMarker = "# BEGIN $block_name";
        $endMarker = "# END $block_name";
        $startIdx = strpos($content, $startMarker);
        if ($startIdx !== false) {
            $endIdx = strpos($content, $endMarker, $startIdx);
            if ($endIdx !== false) {
                $endIdx += strlen($endMarker);
                return substr($content, 0, $startIdx) . substr($content, $endIdx);
            }
        }
        return $content;
    }

    public function auto_correct_htaccess($content) {
        return preg_replace("/\s+\n/", "\n", trim($content));
    }

    public function send_email_notifications($details) {
        $admin_email = get_option('admin_email');
        $subject = 'Alert: .htaccess Changed';
        $message = "The .htaccess file was changed by " . wp_get_current_user()->user_login . "\nDetails: $details";
        wp_mail($admin_email, $subject, $message);
    }

    public function enable_live_tester($content, $file_to_test) {
        if (!$this->validate_htaccess($content)) {
            return ['success' => false, 'message' => 'Invalid .htaccess syntax detected.'];
        }

        $original_content = file_exists($file_to_test) ? file_get_contents($file_to_test) : '';
        $temp_backup = $this->backup_dir . 'test-backup-' . time() . '.bak';

        if (!copy($file_to_test, $temp_backup)) {
            return ['success' => false, 'message' => 'Failed to create test backup.'];
        }

        if (!file_put_contents($file_to_test, $content)) {
            unlink($temp_backup);
            return ['success' => false, 'message' => 'Failed to write test .htaccess.'];
        }

        $test_url = $file_to_test === $this->root_htaccess ? home_url() : admin_url();
        $response = wp_remote_get($test_url, ['timeout' => 5, 'sslverify' => false]);

        if (!copy($temp_backup, $file_to_test)) {
            error_log('WP HTAccess Manager: Failed to restore original .htaccess after test.');
        }
        unlink($temp_backup);

        if (is_wp_error($response)) {
            return ['success' => false, 'message' => 'Test failed: ' . $response->get_error_message()];
        }

        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code === 200) {
            return ['success' => true, 'message' => 'Rules tested successfully (HTTP 200).'];
        } else {
            return ['success' => false, 'message' => "Test returned HTTP $status_code. Check your rules."];
        }
    }

    public function get_backups($file_type) {
        $pattern = $this->backup_dir . $file_type . '-htaccess-*.bak';
        return glob($pattern);
    }

    private function set_admin_notice($message, $type = 'success') {
        set_transient('htaccess_manager_notice', ['message' => $message, 'type' => $type], 30); // Store for 30 seconds
    }
    
    public function display_admin_notices() {
        if ($notice = get_transient('htaccess_manager_notice')) {
            $class = $notice['type'] === 'success' ? 'notice-success' : 'notice-error';
            echo '<div class="notice ' . esc_attr($class) . '"><p>' . esc_html($notice['message']) . '</p></div>';
            delete_transient('htaccess_manager_notice'); // Clear after displaying
        }
    }

    public function ajax_delete_backup() {
        if (!check_ajax_referer('htaccess_delete_nonce', 'nonce', false)) {
            $this->set_admin_notice('Nonce verification failed during backup deletion.', 'error');
            wp_send_json(['success' => false]);
            return;
        }
    
        $backup_file = sanitize_file_name($_POST['backup'] ?? '');
        $file_type = $_POST['file'] === 'admin' ? 'admin' : 'root';
        $backup_path = $this->backup_dir . $backup_file;
    
        if (!file_exists($backup_path)) {
            $this->set_admin_notice('Backup file not found.', 'error');
            wp_send_json(['success' => false]);
            return;
        }
    
        if (unlink($backup_path)) {
            $this->log_changes('', "Deleted backup: $backup_file");
            $this->set_admin_notice("Backup $backup_file deleted successfully.", 'success');
            wp_send_json(['success' => true]);
        } else {
            $this->set_admin_notice('Failed to delete backup file.', 'error');
            wp_send_json(['success' => false]);
        }
    }

    private function scan_existing_htaccess($file_type) {
        $file_path = $file_type === 'admin' ? $this->admin_htaccess : $this->root_htaccess;
        $content = file_exists($file_path) ? file_get_contents($file_path) : '';
        if ($content) {
            $custom_rules = $this->extract_custom_rules($content);
            if ($custom_rules) {
                update_option("htaccess_manager_custom_rules_{$file_type}", $custom_rules);
                $this->set_admin_notice("Existing {$file_type} .htaccess detected. Custom rules preserved and backup created.", 'success');
            }
        }
    }

    private function extract_custom_rules($content) {
        $known_blocks = [
            '# BEGIN WordPress', '# END WordPress',
            '# BEGIN LSCACHE', '# END LSCACHE',
            '# BEGIN Wordfence WAF', '# END Wordfence WAF',
            // Add more known markers as needed (e.g., W3 Total Cache, Yoast SEO)
        ];
        $lines = explode("\n", $content);
        $custom = [];
        $in_known_block = false;
        $block_start = '';
    
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
    
            if (in_array($line, $known_blocks)) {
                if (strpos($line, '# BEGIN') === 0) {
                    $in_known_block = true;
                    $block_start = $line;
                } elseif (strpos($line, '# END') === 0 && $in_known_block && strpos($line, substr($block_start, 8)) !== false) {
                    $in_known_block = false;
                }
                continue;
            }
    
            if (!$in_known_block && $line[0] !== '#') { // Ignore comments outside blocks
                $custom[] = $line;
            }
        }
    
        return !empty($custom) ? implode("\n", $custom) : '';
    }

    public static function activate() {
        $backup_dir = plugin_dir_path(__FILE__) . 'backups' . DIRECTORY_SEPARATOR;
        if (!file_exists($backup_dir)) {
            wp_mkdir_p($backup_dir);
        }
        $instance = new self();
        $instance->backup_htaccess('root', 'initial-' . date('Y-m-d_H-i-s'));
        $instance->backup_htaccess('admin', 'initial-' . date('Y-m-d_H-i-s'));
        $instance->scan_existing_htaccess('root');
        $instance->scan_existing_htaccess('admin');
    }

    public static function deactivate() {
        // Cleanup if needed
    }
}

function wp_htaccess_manager_init() {
    new WP_HTAccess_Manager();
}
add_action('plugins_loaded', 'wp_htaccess_manager_init');

register_activation_hook(__FILE__, ['WP_HTAccess_Manager', 'activate']);
register_deactivation_hook(__FILE__, ['WP_HTAccess_Manager', 'deactivate']);