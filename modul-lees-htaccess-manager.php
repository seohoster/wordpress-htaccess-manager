<?php
/**
 * Plugin Name: Lee's .htaccess Manager by Magazinon.ro
 * Description: A lightweight plugin by Lee from Magazinon.ro to manage root and wp-admin .htaccess files with predefined blocks. Free to use, brought to you with love from Lee!
 * Version: 1.9.35
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
        
        // New backup directory location outside plugin folder
        $this->backup_dir = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'htaccess-backups' . DIRECTORY_SEPARATOR;
        $this->log_file = $this->backup_dir . 'htaccess_manager.log';

        // Add login nonce hook
        add_action('login_form', [$this, 'add_login_nonce_field']);

        $this->blocks = [
            'LSCACHE' => "# BEGIN LSCACHE\n\t# LiteSpeed Cache Optimization\n\t<IfModule LiteSpeed>\n\t\tCacheEnable public /\n\t\tRewriteEngine On\n\t\tRewriteRule .* - [E=cache-control:max-age=120]\n\t</IfModule>\n# END LSCACHE\n",
            'BROWSER_CACHE' => "# BEGIN BROWSER_CACHE\n\t# Enable Browser Caching\n\t<IfModule mod_expires.c>\n\t\tExpiresActive On\n\t\tExpiresByType image/jpg \"access plus 1 year\"\n\t\tExpiresByType image/jpeg \"access plus 1 year\"\n\t\tExpiresByType image/gif \"access plus 1 year\"\n\t\tExpiresByType image/png \"access plus 1 year\"\n\t\tExpiresByType text/css \"access plus 1 month\"\n\t\tExpiresByType application/javascript \"access plus 1 month\"\n\t</IfModule>\n# END BROWSER_CACHE\n",
            'GZIP_COMPRESSION' => "# BEGIN GZIP_COMPRESSION\n\t# Enable GZIP Compression\n\t<IfModule mod_deflate.c>\n\t\tAddOutputFilterByType DEFLATE text/html\n\t\tAddOutputFilterByType DEFLATE text/css\n\t\tAddOutputFilterByType DEFLATE application/javascript\n\t\tBrowserMatch ^Mozilla/4 gzip-only-text/html\n\t\tBrowserMatch ^Mozilla/4\\.0[678] no-gzip\n\t\tBrowserMatch \\bMSIE !no-gzip !gzip-only-text/html\n\t</IfModule>\n# END GZIP_COMPRESSION\n",
            'SECURITY_WP_CONFIG' => "# BEGIN SECURITY_WP_CONFIG\n\t# Block Access to wp-config.php\n\t<IfModule mod_rewrite.c>\n\t\tRewriteRule ^wp-config\\.php$ - [F,L]\n\t</IfModule>\n# END SECURITY_WP_CONFIG\n",
            'BLOCK_XMLRPC' => "# BEGIN BLOCK_XMLRPC\n\t# Block XML-RPC\n\t<Files xmlrpc.php>\n\t\tOrder Deny,Allow\n\t\tDeny from all\n\t</Files>\n# END BLOCK_XMLRPC\n",
            'SECURITY_NO_INDEX' => "# BEGIN SECURITY_NO_INDEX\nOptions -Indexes\n# END SECURITY_NO_INDEX\n",
            'SECURITY_HT_FILES' => "# BEGIN SECURITY_HT_FILES\n\t# Block Access to .htaccess and .htpasswd\n\t<FilesMatch \"^\\.(htaccess|htpasswd)$\">\n\t\tOrder Deny,Allow\n\t\tDeny from all\n\t</FilesMatch>\n# END SECURITY_HT_FILES\n",
            'REDIRECT_HTTPS' => "# BEGIN REDIRECT_HTTPS\n\t# Force HTTPS\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTPS} !=on\n\t\tRewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]\n\t</IfModule>\n# END REDIRECT_HTTPS\n",
            'WP_LOGIN_PASSWORD' => "# BEGIN WP_LOGIN_PASSWORD\n\t# Password Protect wp-login.php\n\t<Files wp-login.php>\n\t\tAuthType Basic\n\t\tAuthName \"Restricted Area\"\n\t\tAuthUserFile {{HOME_URL}}/.htpasswd\n\t\tRequire valid-user\n\t</Files>\n# END WP_LOGIN_PASSWORD\n",
            'CORS_ORIGIN' => "# BEGIN CORS_ORIGIN\n\t# Fix CORS for Fonts and Assets\n\t<IfModule mod_headers.c>\n\t\t<FilesMatch \"\\.(ttf|otf|eot|woff|woff2)$\">\n\t\t\tHeader set Access-Control-Allow-Origin \"*\"\n\t\t</FilesMatch>\n\t</IfModule>\n# END CORS_ORIGIN\n",
            'PHP_TWEAKS' => "# BEGIN PHP_TWEAKS\n\tphp_value upload_max_filesize 20M\n\tphp_value post_max_size 20M\n\tphp_value memory_limit 256M\n# END PHP_TWEAKS\n",
            'MOD_SECURITY' => "# BEGIN MOD_SECURITY\n\t# Enable ModSecurity\n\t<IfModule mod_security.c>\n\t\tSecFilterEngine On\n\t\tSecFilterScanPOST On\n\t</IfModule>\n# END MOD_SECURITY\n",
            'ANTI_XSS' => "# BEGIN ANTI_XSS\n\t# Anti-XSS and SQL Injection Protection\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3E) [NC,OR]\n\t\tRewriteCond %{QUERY_STRING} GLOBALS= [NC,OR]\n\t\tRewriteCond %{QUERY_STRING} _REQUEST= [NC,OR]\n\t\tRewriteCond %{QUERY_STRING} (union|select|insert|drop|update|md5|benchmark|alter|delete|truncate|where|base64_decode|eval\\() [NC,OR]\n\t\tRewriteCond %{QUERY_STRING} (javascript:|alert\\() [NC,OR]\n\t\tRewriteCond %{HTTP_USER_AGENT} (libwww-perl|wget|curl|nikto|sqlmap) [NC]\n\t\tRewriteRule .* - [F,L]\n\t</IfModule>\n# END ANTI_XSS\n",
            'HOTLINK_PROTECTION' => "# BEGIN HOTLINK_PROTECTION\n\t# Prevent Hotlinking (bypassed on localhost)\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTP_HOST} !^(localhost|127\\.0\\.0\\.1)$ [NC]\n\t\tRewriteCond %{HTTP_REFERER} !^$\n\t\tRewriteCond %{HTTP_REFERER} !^https?://(www\\.)?{{HOME_URL}}/ [NC]\n\t\tRewriteRule \\.(jpg|jpeg|png|gif|webp|pdf|svg)$ - [F,L]\n\t</IfModule>\n# END HOTLINK_PROTECTION\n",
            'BLOCK_AI_BOTS' => "# BEGIN BLOCK_AI_BOTS\n\t# Block AI Scraping Bots\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTP_USER_AGENT} (GPTBot|ClaudeBot|Google-Extended) [NC]\n\t\tRewriteRule .* - [F,L]\n\t</IfModule>\n# END BLOCK_AI_BOTS\n",
            'LIMIT_UPLOAD_SIZE' => "# BEGIN LIMIT_UPLOAD_SIZE\n\tphp_value upload_max_filesize 10M\n\tphp_value post_max_size 10M\n# END LIMIT_UPLOAD_SIZE\n",
            'DISABLE_PHP_UPLOADS' => "# BEGIN DISABLE_PHP_UPLOADS\n\t# Disable PHP in wp-content/uploads\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteRule ^wp-content/uploads/.*\\.php$ - [F,L]\n\t</IfModule>\n# END DISABLE_PHP_UPLOADS\n",
            'FORCE_DOWNLOAD' => "# BEGIN FORCE_DOWNLOAD\n\t# Force Downloads for Certain File Types\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteRule \\.(pdf|zip|rar)$ - [R=302,L]\n\t</IfModule>\n# END FORCE_DOWNLOAD\n",
            'REDIRECT_WWW' => "# BEGIN REDIRECT_WWW\n\t# Force non-www\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\n\t\tRewriteRule ^(.*)$ https://%1/$1 [R=301,L]\n\t</IfModule>\n# END REDIRECT_WWW\n",
            'HSTS_HEADER' => "# BEGIN HSTS_HEADER\n\t# Enable HSTS\n\t<IfModule mod_headers.c>\n\t\tHeader set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" env=HTTPS\n\t</IfModule>\n# END HSTS_HEADER\n",
            'SECURITY_HEADERS' => "# BEGIN SECURITY_HEADERS\n\t# Additional Security Headers\n\t<IfModule mod_headers.c>\n\t\tHeader set X-XSS-Protection \"1; mode=block\"\n\t\tHeader set X-Content-Type-Options \"nosniff\"\n\t\tHeader set X-Permitted-Cross-Domain-Policies \"none\"\n\t\tHeader set X-Frame-Options \"SAMEORIGIN\"\n\t\tHeader set Referrer-Policy \"no-referrer-when-downgrade\"\n\t</IfModule>\n# END SECURITY_HEADERS\n",
            'DISABLE_USER_ENUM' => "# BEGIN DISABLE_USER_ENUM\n\t# Disable User Enumeration\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteBase /\n\t\tRewriteCond %{QUERY_STRING} ^author=([0-9]+) [NC]\n\t\tRewriteRule .* - [F,L]\n\t</IfModule>\n# END DISABLE_USER_ENUM\n",
            'DISABLE_PHP_WPINCLUDES' => "# BEGIN DISABLE_PHP_WPINCLUDES\n\t# Disable PHP in wp-includes\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteRule ^wp-includes/.*\\.php$ - [F,L]\n\t</IfModule>\n# END DISABLE_PHP_WPINCLUDES\n",
            'DISABLE_PHP_WPCONTENT' => "# BEGIN DISABLE_PHP_WPCONTENT\n\t# Disable PHP in wp-content (except plugins/themes)\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteRule ^wp-content/(?!plugins/|themes/).*\\.php$ - [F,L]\n\t</IfModule>\n# END DISABLE_PHP_WPCONTENT\n",
            'PREVENT_BRUTE_FORCE_WP_LOGIN' => "# BEGIN PREVENT_BRUTE_FORCE_WP_LOGIN\n\t# Prevent Brute Force on wp-login.php with Nonce\n\t<IfModule mod_rewrite.c>\n\t\tRewriteCond %{REQUEST_METHOD} POST\n\t\tRewriteCond %{REQUEST_URI} ^(.*)?wp-login\\.php(.*)$\n\t\tRewriteCond %{QUERY_STRING} !login_nonce=([^&]+) [NC]\n\t\tRewriteRule .* - [F,L]\n\t</IfModule>\n# END PREVENT_BRUTE_FORCE_WP_LOGIN\n",
            'FILE_SCRIPT_PROTECTION' => "# BEGIN FILE_SCRIPT_PROTECTION\n\t# Protect Sensitive Files and Block Hidden Files\n\t<IfModule mod_rewrite.c>\n\t\tRewriteRule ^wp-content/uploads/.*\\.(log|bak|sql|zip)$ - [F]\n\t\tRewriteRule ^\\.(?!well-known).* - [F]\n\t</IfModule>\n# END FILE_SCRIPT_PROTECTION\n"
        ];
    
        $this->block_descriptions = [
            'LSCACHE' => 'Optimizes caching for LiteSpeed servers.',
            'BROWSER_CACHE' => 'Enables browser caching for static assets like images and scripts.',
            'GZIP_COMPRESSION' => 'Compresses content to speed up page loads.',
            'SECURITY_WP_CONFIG' => 'Blocks access to wp-config.php.',
            'BLOCK_XMLRPC' => 'Disables XML-RPC to prevent brute-force attacks.',
            'SECURITY_NO_INDEX' => 'Prevents directory listing.',
            'SECURITY_HT_FILES' => 'Blocks access to .htaccess and similar files.',
            'REDIRECT_HTTPS' => 'Forces all traffic to HTTPS.',
            'WP_LOGIN_PASSWORD' => 'Adds password protection to wp-login.php (requires .htpasswd).',
            'CORS_ORIGIN' => 'Fixes CORS issues for fonts and assets.',
            'PHP_TWEAKS' => 'Adjusts PHP settings for better performance.',
            'MOD_SECURITY' => 'Enables ModSecurity filters for extra protection.',
            'ANTI_XSS' => 'Blocks XSS, SQL injection, and malicious user agents in query strings.',
            'HOTLINK_PROTECTION' => 'Prevents other sites from hotlinking your files (disabled on localhost).',
            'BLOCK_AI_BOTS' => 'Blocks AI scraping bots like GPTBot and ClaudeBot.',
            'LIMIT_UPLOAD_SIZE' => 'Caps upload size at 10MB to prevent abuse.',
            'DISABLE_PHP_UPLOADS' => 'Blocks PHP execution in wp-content/uploads.',
            'FORCE_DOWNLOAD' => 'Forces downloads for PDFs, ZIPs, and RARs.',
            'REDIRECT_WWW' => 'Forces non-www URLs (toggleable to www).',
            'HSTS_HEADER' => 'Enforces HTTPS with HSTS for a year, with preload support.',
            'SECURITY_HEADERS' => 'Adds security headers to protect against common web vulnerabilities.',
            'DISABLE_USER_ENUM' => 'Prevents user enumeration via author query strings.',
            'DISABLE_PHP_WPINCLUDES' => 'Blocks PHP execution in wp-includes directory.',
            'DISABLE_PHP_WPCONTENT' => 'Blocks PHP execution in wp-content, except in plugins and themes.',
            'PREVENT_BRUTE_FORCE_WP_LOGIN' => 'Blocks unauthorized POST requests to wp-login.php without a valid nonce, preventing brute force attacks.',
            'FILE_SCRIPT_PROTECTION' => 'Blocks access to sensitive file types in uploads and hidden files except .well-known.'
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

    public function add_login_nonce_field() { // Used togheter with the PREVENT_BRUTE_FORCE_WP_LOGIN rule
        $nonce = wp_create_nonce('login_nonce');
        echo '<input type="hidden" name="login_nonce" value="' . esc_attr($nonce) . '" />';
        // Add nonce to form action URL to make it visible to .htaccess
        echo '<script>document.getElementById("loginform").action += "?login_nonce=' . esc_js($nonce) . '";</script>';
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
            <h1>Lee's .htaccess Manager</h1>
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
                delete_transient('htaccess_manager_test_content');
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

            // Delete All Rules button handler - Modified to remove LSCACHE
            $('#delete-all-rules').on('click', function() {
                if (!confirm('Are you sure you want to delete all custom rules? This will keep only WordPress and Wordfence WAF rules if present.')) {
                    return;
                }

                var currentContent = editor.getValue().trim();
                var newContent = '';
                var wpBlock = '';
                var wordfenceBlock = '';

                var wpStart = currentContent.indexOf('# BEGIN WordPress');
                if (wpStart !== -1) {
                    var wpEnd = currentContent.indexOf('# END WordPress', wpStart);
                    if (wpEnd !== -1) {
                        wpEnd += '# END WordPress'.length;
                        wpBlock = currentContent.substring(wpStart, wpEnd).trim();
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

                // Only keep WordPress and Wordfence WAF, remove LSCACHE
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
                        editor_content: content
                    },
                    success: function(response) {
                        if (response.success) {
                            location.reload();
                        } else {
                            location.reload();
                        }
                    },
                    error: function(xhr, status, error) {
                        console.log('Test AJAX error: ' + error);
                        location.reload();
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
                                location.reload();
                            } else {
                                location.reload();
                            }
                        },
                        error: function(xhr, status, error) {
                            console.log('Restore AJAX error: ' + error);
                            location.reload();
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
                                location.reload();
                            } else {
                                location.reload();
                            }
                        },
                        error: function(xhr, status, error) {
                            console.log('Delete AJAX error: ' + error);
                            location.reload();
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

    private function migrate_backups() {
        $old_backup_dir = plugin_dir_path(__FILE__) . 'backups' . DIRECTORY_SEPARATOR;
        if (file_exists($old_backup_dir)) {
            $old_backups = glob($old_backup_dir . '*.bak');
            foreach ($old_backups as $backup) {
                $filename = basename($backup);
                copy($backup, $this->backup_dir . $filename);
            }
        }
    }

    private function rotate_backups($file_type, $max_backups = 10) {
        $backups = $this->get_backups($file_type);
        if (count($backups) > $max_backups) {
            usort($backups, function($a, $b) {
                return filemtime($a) - filemtime($b);
            });
            $to_delete = array_slice($backups, 0, count($backups) - $max_backups);
            foreach ($to_delete as $backup) {
                unlink($backup);
            }
        }
    }

    public static function activate() {
        // Create backup directory in wp-content
        $backup_dir = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'htaccess-backups' . DIRECTORY_SEPARATOR;
        if (!file_exists($backup_dir)) {
            wp_mkdir_p($backup_dir);
            
            // Create .htaccess to protect the directory
            $htaccess_content = "# Protect htaccess backups directory\n";
            $htaccess_content .= "<Files ~ \"\.bak$\">\n";
            $htaccess_content .= "    Order allow,deny\n";
            $htaccess_content .= "    Deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "# Disable directory browsing\n";
            $htaccess_content .= "Options -Indexes\n";
            
            file_put_contents($backup_dir . '.htaccess', $htaccess_content);
            
            // Create empty index.php file for additional security
            file_put_contents($backup_dir . 'index.php', '<?php // Silence is golden');
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