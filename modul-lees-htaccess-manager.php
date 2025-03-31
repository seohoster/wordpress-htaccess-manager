<?php
/**
 * Plugin Name: Lee's .htaccess Manager by Lee @ Magazinon.ro
 * Description: A lightweight plugin by Lee @ Magazinon.ro to manage root and wp-admin .htaccess files with predefined blocks.
 * Version: 1.9.57  
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
 * 13. check_permissions() - Verifies user permissions and file writability, with enhanced diagnostics
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
 * 24. migrate_backups() - Migrates old backups to the new backup directory
 * 25. rotate_backups() - Rotates backups to maintain a maximum number of backups
 * 26. add_login_nonce_field() - Adds a nonce field to the login form
 * 27. validate_login_nonce() - Validates the login nonce during authentication
 * 28. set_rate_limit_cookie() - Sets rate limit exemption cookie for admin
 * 29. activate() - Plugin activation hook
 * 30. deactivate() - Plugin deactivation hook
 * 31. write_file_with_fallback() - Attempts to write to a file with WP_Filesystem fallback
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
        add_action('wp_authenticate', [$this, 'validate_login_nonce'], 1);
        add_action('admin_init', [$this, 'set_rate_limit_cookie']);
    
        $this->blocks = [
            // Admin-Specific Blocks
            'ADMIN_IP_RESTRICT' => "# BEGIN ADMIN_IP_RESTRICT\n\t# Restrict wp-admin to specific IPs\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{REMOTE_ADDR} !^127\\.0\\.0\\.1$ [NC]\n\t\t# Add more IPs below as needed (e.g., RewriteCond %{REMOTE_ADDR} !^203\\.0\\.113\\.50$)\n\t\tRewriteRule .* - [F,L]\n\t</IfModule>\n# END ADMIN_IP_RESTRICT\n",
            'ADMIN_BASIC_AUTH' => "# BEGIN ADMIN_BASIC_AUTH\n\t# Password protect wp-admin\n\tAuthType Basic\n\tAuthName \"Admin Restricted Area\"\n\tAuthUserFile {{HOME_PATH}}/.htpasswd\n\tRequire valid-user\n\t# Allow AJAX requests without auth\n\t<Files \"admin-ajax.php\">\n\t\tOrder allow,deny\n\t\tAllow from all\n\t\tSatisfy any\n\t</Files>\n# END ADMIN_BASIC_AUTH\n",
            'ADMIN_BLOCK_PHP' => "# BEGIN ADMIN_BLOCK_PHP\n\t# Block non-existent PHP files in wp-admin\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{DOCUMENT_ROOT}%{REQUEST_URI} !-f\n\t\tRewriteRule \\.php$ - [F,L]\n\t</IfModule>\n# END ADMIN_BLOCK_PHP\n",
            'ADMIN_NO_INDEX' => "# BEGIN ADMIN_NO_INDEX\n\tOptions -Indexes\n# END ADMIN_NO_INDEX\n",
            'ADMIN_RATE_LIMIT' => "# BEGIN ADMIN_RATE_LIMIT\n\t# Basic rate-limiting for wp-admin\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{REQUEST_URI} ^/wp-admin/.*$\n\t\tRewriteCond %{HTTP_COOKIE} !rate_limit_exempt=1 [NC]\n\t\tRewriteRule .* - [R=429,L]\n\t</IfModule>\n# END ADMIN_RATE_LIMIT\n",
            'ADMIN_HTTPS' => "# BEGIN ADMIN_HTTPS\n\t# Force HTTPS for wp-admin\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTPS} !=on\n\t\tRewriteRule ^(.*)$ https://%{HTTP_HOST}/wp-admin/$1 [R=301,L]\n\t</IfModule>\n# END ADMIN_HTTPS\n",
            'BLOCK_BAD_BOTS' => "# BEGIN BLOCK_BAD_BOTS\n\t# Block known bad bots site-wide\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTP_USER_AGENT} (abot|aipbot|asterias|EI|libwww-perl|LWP|lwp|MSIECrawler|nameprotect|PlantyNet_WebRobot|UCmore|Alligator|AllSubmitter|Anonymous|Asterias|autoemailspider|Badass|Baiduspider|BecomeBot|Bitacle|bladder\\ fusion|Blogshares\\ Spiders|Board\\ Bot|Convera|ConveraMultiMediaCrawler|c-spider|DA|DnloadMage|Download\\ Demon|Download\\ Express|Download\\ Wonder|dragonfly|DreamPassport|DSurf|DTS\\ Agent|EBrowse|eCatch|edgeio|Email\\ Extractor|EmailSiphon|EmailWolf|EmeraldShield|ESurf|Exabot|ExtractorPro|FileHeap!\\ file\\ downloader|FileHound|Forex|Franklin\\ Locator|FreshDownload|FrontPage|FSurf|Gaisbot|Gamespy_Arcade|genieBot|GetBot|GetRight|Gigabot|Go!Zilla|Go-Ahead-Got-It|GOFORITBOT|heritrix|HLoader|HooWWWer|HTTrack|iCCrawler|ichiro|iGetter|imds_monitor|Industry\\ Program|Indy\\ Library|InetURL|InstallShield\\ DigitalWizard|IRLbot|IUPUI\\ Research\\ Bot|Java|jeteye|jeteyebot|JoBo|JOC\\ Web\\ Spider|Kapere|Larbin|LeechGet|LightningDownload|Linkie|Mac\\ Finder|Mail\\ Sweeper|Mass\\ Downloader|MetaProducts\\ Download\\ Express|Microsoft\\ Data\\ Access|Microsoft\\ URL\\ Control|Missauga\\ Locate|Missauga\\ Locator|Missigua\\ Locator|Missouri\\ College\\ Browse|Mister\\ PiX|MovableType|Mozi!|Mozilla\\/3\\.0\\ \\(compatible\\)|Mozilla\\/5\\.0\\ \\(compatible;\\ MSIE\\ 5\\.0\\)|MSIE_6\\.0|MSIECrawler|MVAClient|MyFamilyBot|MyGetRight|NASA\\ Search|Naver|NaverBot|NetAnts|NetResearchServer|NEWT\\ ActiveX|Nextopia|NICErsPRO|NimbleCrawler|Nitro\\ Downloader|Nutch|Offline\\ Explorer|OmniExplorer|OutfoxBot|P3P|PagmIEDownload|pavuk|PHP\\ version|playstarmusic|Program\\ Shareware|Progressive\\ Download|psycheclone|puf|PussyCat|PuxaRapido|Python-urllib|RealDownload|RedKernel|relevantnoise|RepoMonkey\\ Bait\\ &\\ Tackle|RTG30|SBIder|script|Seekbot|SiteSnagger|SmartDownload|sna-|Snap\\ bot|SpeedDownload|Sphere|sproose|SQ\\ Webscanner|Stamina|Star\\ Downloader|Teleport|TurnitinBot|UdmSearch|URLGetFile|User-Agent|UtilMind\\ HTTPGet|WebAuto|WebCapture|webcollage|WebCopier|WebFilter|WebReaper|Website\\ eXtractor|WebStripper|WebZIP|Wells\\ Search|WEP\\ Search\\ 00|Wget|Wildsoft\\ Surfer|WinHttpRequest|WWWOFFLE|Xaldon\\ WebSpider|Y!TunnelPro|YahooYSMcm|Zade|ZBot|zerxbot) [NC]\n\t\tRewriteRule .* - [F,L]\n\t</IfModule>\n# END BLOCK_BAD_BOTS\n",
            'BLOCK_AI_BOTS' => "# BEGIN BLOCK_AI_BOTS\n\t# Block AI Scraping Bots\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTP_USER_AGENT} (CCBot|ChatGPT|GPTBot|anthropic-ai|Omgilibot|Omgili|FacebookBot|Diffbot|Bytespider|ImagesiftBot|cohere-ai|ClaudeBot) [NC]\n\t\tRewriteRule .* - [F,L]\n\t</IfModule>\n# END BLOCK_AI_BOTS\n",
            'LSCACHE' => "# BEGIN LSCACHE\n\t# LiteSpeed Cache Optimization\n\t<IfModule LiteSpeed>\n\t\tCacheEnable public /\n\t\tRewriteEngine On\n\t\tRewriteRule .* - [E=cache-control:max-age=120]\n\t</IfModule>\n# END LSCACHE\n",
            'BROWSER_CACHE' => "# BEGIN BROWSER_CACHE\n\t# Enable Browser Caching\n\t<IfModule mod_expires.c>\n\t\tExpiresActive On\n\t\tExpiresByType image/jpg \"access plus 1 year\"\n\t\tExpiresByType image/jpeg \"access plus 1 year\"\n\t\tExpiresByType image/gif \"access plus 1 year\"\n\t\tExpiresByType image/png \"access plus 1 year\"\n\t\tExpiresByType text/css \"access plus 1 month\"\n\t\tExpiresByType application/javascript \"access plus 1 month\"\n\t</IfModule>\n# END BROWSER_CACHE\n",
            'GZIP_COMPRESSION' => "# BEGIN GZIP_COMPRESSION\n\t# Enable GZIP Compression\n\t<IfModule mod_deflate.c>\n\t\tAddOutputFilterByType DEFLATE text/html\n\t\tAddOutputFilterByType DEFLATE text/css\n\t\tAddOutputFilterByType DEFLATE application/javascript\n\t\tBrowserMatch ^Mozilla/4 gzip-only-text/html\n\t\tBrowserMatch ^Mozilla/4\\.0[678] no-gzip\n\t\tBrowserMatch \\bMSIE !no-gzip !gzip-only-text/html\n\t</IfModule>\n# END GZIP_COMPRESSION\n",
            'SECURITY_WP_CONFIG' => "# BEGIN SECURITY_WP_CONFIG\n\t# Block Access to wp-config.php\n\t<IfModule mod_rewrite.c>\n\t\tRewriteRule ^wp-config\\.php$ - [F,L]\n\t</IfModule>\n# END SECURITY_WP_CONFIG\n",
            'BLOCK_XMLRPC' => "# BEGIN BLOCK_XMLRPC\n\t# Block XML-RPC\n\t<Files xmlrpc.php>\n\t\tOrder Deny,Allow\n\t\tDeny from all\n\t</Files>\n# END BLOCK_XMLRPC\n",
            'SECURITY_NO_INDEX' => "# BEGIN SECURITY_NO_INDEX\nOptions -Indexes\n# END SECURITY_NO_INDEX\n",
            'SECURITY_HT_FILES' => "# BEGIN SECURITY_HT_FILES\n\t# Block Access to .htaccess and .htpasswd\n\t<FilesMatch \"^\\.(htaccess|htpasswd)$\">\n\t\tOrder Deny,Allow\n\t\tDeny from all\n\t</FilesMatch>\n# END SECURITY_HT_FILES\n",
            'REDIRECT_HTTPS' => "# BEGIN REDIRECT_HTTPS\n\t# Force HTTPS\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTPS} !=on\n\t\tRewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]\n\t</IfModule>\n# END REDIRECT_HTTPS\n",
            'WP_LOGIN_PASSWORD' => "# BEGIN WP_LOGIN_PASSWORD\n\t# Password Protect wp-login.php\n\t<Files wp-login.php>\n\t\tAuthType Basic\n\t\tAuthName \"Restricted Area\"\n\t\tAuthUserFile {{HOME_URL}}/.htpasswd\n\t\tRequire valid-user\n\t</Files>\n# END WP_LOGIN_PASSWORD\n",
            'CORS_ORIGIN' => "# BEGIN CORS_ORIGIN\n\t# Fix CORS for Fonts and Assets\n\t<IfModule mod_headers.c>\n\t\t<FilesMatch \"\\.(ttf|ttc|otf|eot|woff|woff2)$\">\n\t\t\tHeader set Access-Control-Allow-Origin \"*\"\n\t\t</FilesMatch>\n\t</IfModule>\n# END CORS_ORIGIN\n",
            'PHP_TWEAKS' => "# BEGIN PHP_TWEAKS\n\tphp_value upload_max_filesize 20M\n\tphp_value post_max_size 20M\n\tphp_value memory_limit 256M\n# END PHP_TWEAKS\n",
            'MOD_SECURITY' => "# BEGIN MOD_SECURITY\n\t# Enable ModSecurity\n\t<IfModule mod_security.c>\n\t\tSecFilterEngine On\n\t\tSecFilterScanPOST On\n\t</IfModule>\n# END MOD_SECURITY\n",
            'BLOCK_XSS_UA' => "# BEGIN BLOCK_XSS_UA\n\t# Block XSS attacks and malicious User-Agents\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\t# XSS: Query string patterns\n\t\tRewriteCond %{QUERY_STRING} (<|%3C).*?(script|img|onerror|alert)[^>]*>|javascript:|alert\\( [NC,OR]\n\t\t# XSS: POST body patterns\n\t\tRewriteCond %{REQUEST_METHOD} POST\n\t\tRewriteCond %{THE_REQUEST} (<|%3C).*?(script|img|onerror|alert)[^>]*> [NC,OR]\n\t\t# Malicious User-Agents\n\t\tRewriteCond %{HTTP_USER_AGENT} (libwww-perl|wget|curl|nikto|sqlmap) [NC]\n\t\tRewriteRule ^ - [F,L]\n\t</IfModule>\n# END BLOCK_XSS_UA\n",
            'HOTLINK_PROTECTION' => "# BEGIN HOTLINK_PROTECTION\n\t# Prevent Hotlinking (bypassed on localhost)\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTP_HOST} !^(localhost|127\\.0\\.0\\.1)$ [NC]\n\t\tRewriteCond %{HTTP_REFERER} !^$\n\t\tRewriteCond %{HTTP_REFERER} !^https?://(www\\.)?{{HOME_URL}}/ [NC]\n\t\tRewriteRule \\.(jpg|jpeg|png|gif|webp|pdf|svg)$ - [F,L]\n\t</IfModule>\n# END HOTLINK_PROTECTION\n",
            'LIMIT_UPLOAD_SIZE' => "# BEGIN LIMIT_UPLOAD_SIZE\n\tphp_value upload_max_filesize 10M\n\tphp_value post_max_size 10M\n# END LIMIT_UPLOAD_SIZE\n",
            'DISABLE_PHP_UPLOADS' => "# BEGIN DISABLE_PHP_UPLOADS\n\t# Disable PHP in wp-content/uploads\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteRule ^wp-content/uploads/.*\\.php$ - [F,L]\n\t</IfModule>\n# END DISABLE_PHP_UPLOADS\n",
            'FORCE_DOWNLOAD' => "# BEGIN FORCE_DOWNLOAD\n\t# Force Downloads for Certain File Types\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteRule \\.(pdf|zip|rar)$ - [R=302,L]\n\t</IfModule>\n# END FORCE_DOWNLOAD\n",
            'REDIRECT_WWW' => "# BEGIN REDIRECT_WWW\n\t# Force non-www\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\n\t\tRewriteRule ^(.*)$ https://%1/$1 [R=301,L]\n\t</IfModule>\n# END REDIRECT_WWW\n",
            'HSTS_HEADER' => "# BEGIN HSTS_HEADER\n\t# Enable HSTS\n\t<IfModule mod_headers.c>\n\t\tHeader set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" env=HTTPS\n\t</IfModule>\n# END HSTS_HEADER\n",
            'SECURITY_HEADERS' => "# BEGIN SECURITY_HEADERS\n\t# Additional Security Headers\n\t<IfModule mod_headers.c>\n\t\tHeader set X-XSS-Protection \"1; mode=block\"\n\t\tHeader set X-Content-Type-Options \"nosniff\"\n\t\tHeader set X-Permitted-Cross-Domain-Policies \"none\"\n\t\tHeader set X-Frame-Options \"SAMEORIGIN\"\n\t\tHeader set Referrer-Policy \"no-referrer-when-downgrade\"\n\t</IfModule>\n# END SECURITY_HEADERS\n",
            'DISABLE_USER_ENUM' => "# BEGIN DISABLE_USER_ENUM\n\t# Disable User Enumeration\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteBase /\n\t\tRewriteCond %{QUERY_STRING} ^author=([0-9]+) [NC]\n\t\tRewriteRule .* - [F,L]\n\t</IfModule>\n# END DISABLE_USER_ENUM\n",
            'DISABLE_PHP_WPINCLUDES' => "# BEGIN DISABLE_PHP_WPINCLUDES\n\t# Disable PHP in wp-includes\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteRule ^wp-includes/.*\\.php$ - [F,L]\n\t</IfModule>\n# END DISABLE_PHP_WPINCLUDES\n",
            'DISABLE_PHP_WPCONTENT' => "# BEGIN DISABLE_PHP_WPCONTENT\n\t# Disable PHP in wp-content (except plugins/themes)\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteRule ^wp-content/(?!plugins/|themes/).*\\.php$ - [F,L]\n\t</IfModule>\n# END DISABLE_PHP_WPCONTENT\n",
            'PREVENT_BRUTE_FORCE_WP_LOGIN' => "# BEGIN PREVENT_BRUTE_FORCE_WP_LOGIN\n\t# Block unauthorized POSTs to wp-login.php without a nonce\n\t<IfModule mod_rewrite.c>\n\t\tRewriteCond %{REQUEST_METHOD} POST\n\t\tRewriteCond %{REQUEST_URI} ^(.*)?wp-login\\.php(.*)$\n\t\tRewriteCond %{QUERY_STRING} !login_nonce=([^&]+) [NC]\n\t\tRewriteRule .* - [F,L]\n\t</IfModule>\n# END PREVENT_BRUTE_FORCE_WP_LOGIN\n",
            'BLOCK_IFRAME' => "# BEGIN BLOCK_IFRAME\n# Block iframe embedding to prevent clickjacking, with exceptions for specific paths\n<IfModule mod_headers.c>\n    # Allow framing for specific paths (add more paths as needed)\n    SetEnvIf Request_URI \"^/example-page\$\" allow_framing=true\n    # Set X-Frame-Options to SAMEORIGIN by default, unless allow_framing is true\n    Header set X-Frame-Options SAMEORIGIN env=!allow_framing\n</IfModule>\n# END BLOCK_IFRAME\n",
            'PROTECT_SENSITIVE_FILES' => "# BEGIN PROTECT_SENSITIVE_FILES\n\t<FilesMatch \"(\\.((bak|config|dist|fla|inc|ini|log|psd|sh|sql|swp|zip)|~)|^(?!\.well-known)\..*\$)\">\n\t    Order allow,deny\n\t    Deny from all\n\t    Satisfy All\n\t</FilesMatch>\n# END PROTECT_SENSITIVE_FILES\n",
            'REDIRECT_DOTS' => "# BEGIN REDIRECT_DOTS\n\tRedirectMatch 404 /\\..*$\n# END REDIRECT_DOTS\n",
            'BLOCK_MALICIOUS_UPLOAD' => "# BEGIN BLOCK_MALICIOUS_UPLOAD\n\t# Block malicious file inclusion or upload attempts via query string, targeting executable extensions\n\t<IfModule mod_rewrite.c>\n\t\tRewriteEngine On\n\t\tRewriteCond %{QUERY_STRING} .*\.(php|phtml|phps|asp|aspx|cgi|pl|py)$ [NC,OR]\n\t\tRewriteCond %{QUERY_STRING} ((\\.\\/|\\.\\%2f|%2e%2e%2f)+) [NC]\n\t\tRewriteRule ^ - [F,L]\n\t</IfModule>\n# END BLOCK_MALICIOUS_UPLOAD\n"
        ];
    
        $this->block_descriptions = [
            'ADMIN_IP_RESTRICT' => 'Restricts wp-admin access to specific IP addresses (default: 127.0.0.1 for localhost). Edit IPs in the rule.',
            'ADMIN_BASIC_AUTH' => 'Adds HTTP Basic Authentication to wp-admin, requiring a username/password from an .htpasswd file. Exempts admin-ajax.php.',
            'ADMIN_BLOCK_PHP' => 'Blocks PHP files in wp-admin that don`t exist, like random.php, with a 403 error. Lets real admin files, like users.php, work normally.',
            'ADMIN_NO_INDEX' => 'Prevents directory listing in wp-admin.',
            'ADMIN_RATE_LIMIT' => 'Basic rate-limiting for wp-admin requests; requires a cookie (rate_limit_exempt=1) to bypass (needs PHP support).',
            'ADMIN_HTTPS' => 'Forces HTTPS for wp-admin only, redirecting HTTP requests to HTTPS.',
            'BLOCK_BAD_BOTS' => 'Blocks known bad bots (e.g., scrapers, downloaders) from the entire site by checking their User-Agent, denying access with a 403 error.',
            'BLOCK_AI_BOTS' => 'Blocks AI scraping bots like CCBot, ChatGPT, GPTBot, and others from the entire site with a 403 error.',
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
            'BLOCK_XSS_UA' => 'Blocks XSS attacks (query strings and POST bodies) and malicious User-Agents.',
            'HOTLINK_PROTECTION' => 'Prevents other sites from hotlinking your files (disabled on localhost).',
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
            'PROTECT_SENSITIVE_FILES' => 'Protects sensitive files (e.g. .bak .config .dist .fla .inc .ini .log .psd .sh .sql .swp .zip) and hidden files like .htpasswd or .htaccess(except .well-known) across the site by denying access.',
            'REDIRECT_DOTS' => 'Redirect all attempts for a .something file to be a 404 not found, confusing attackers. FUN!', # made irelevant by the PROTECT_SENSITIVE_FILES code block
            'BLOCK_SQL_INJECTION' => 'Blocks SQL Injection attacks by detecting malicious patterns and specific parameter exploits in query strings.',
            'BLOCK_IFRAME' => 'Blocks iframe embedding to prevent clickjacking by setting X-Frame-Options to SAMEORIGIN, with exceptions for specific paths (e.g., /example-page).  ',
            'BLOCK_FILE_TRAVERSAL_INCLUSION' => 'Blocks Directory Traversal and Local File Inclusion (LFI) attacks by detecting traversal patterns and sensitive file access.',
            'BLOCK_MALICIOUS_UPLOAD' => 'Blocks malicious file inclusion or upload attempts via query strings by detecting executable extensions (e.g., .php, .asp) and directory traversal patterns, regardless of parameter name.'
        ];
    
        add_action('admin_menu', [$this, 'add_admin_page']);
        add_action('admin_init', [$this, 'handle_form_submission']);
        add_action('admin_enqueue_scripts', [$this, 'load_admin_assets']);
        add_action('wp_ajax_test_htaccess', [$this, 'ajax_test_htaccess']);
        add_action('wp_ajax_restore_backup', [$this, 'ajax_restore_backup']);
        add_action('wp_ajax_backup_htaccess', [$this, 'ajax_backup_htaccess']);
        add_action('wp_ajax_delete_backup', [$this, 'ajax_delete_backup']);
        add_action('admin_notices', [$this, 'display_admin_notices']);
        if (is_admin()) {
            $this->check_permissions();
        }
    }

    public function validate_login_nonce() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['login_nonce'])) {
            $nonce = sanitize_text_field($_GET['login_nonce']);
            if (!wp_verify_nonce($nonce, 'login_nonce')) {
                wp_die('Invalid login attempt. Please try again.', 'Forbidden', ['response' => 403]);
            }
        }
    }

    public function set_rate_limit_cookie() {
        if (!isset($_COOKIE['rate_limit_exempt'])) {
            setcookie('rate_limit_exempt', '1', time() + 3600, '/wp-admin/');
        }
    }    

    /*
    public function add_login_nonce_field() { // Used togheter with the PREVENT_BRUTE_FORCE_WP_LOGIN rule
        $nonce = wp_create_nonce('login_nonce');
        echo '<input type="hidden" name="login_nonce" value="' . esc_attr($nonce) . '" />';
        // Add nonce to form action URL to make it visible to .htaccess
        echo '<script>document.getElementById("loginform").action += "?login_nonce=' . esc_js($nonce) . '";</script>';
    }
    */
    
    public function add_login_nonce_field() {
        $nonce = wp_create_nonce('login_nonce');
        echo '<input type="hidden" name="login_nonce" value="' . esc_attr($nonce) . '" />';
        $action_url = esc_url(add_query_arg('login_nonce', $nonce, wp_login_url()));
        echo '<script>document.getElementById("loginform").action = "' . $action_url . '";</script>';
    }
    
/*  // not working as expected
    public function add_login_nonce_field() {
        wp_enqueue_script('jquery');
        $nonce = wp_create_nonce('login_nonce');
        echo '<input type="hidden" name="login_nonce" value="' . esc_attr($nonce) . '" />';
        echo '<script>
            jQuery(document).ready(function($) {
                $("#loginform").attr("action", function(i, val) {
                    return val + "?login_nonce=' . esc_js($nonce) . '";
                });
            });
        </script>';
        // Server-side fallback
        add_filter('login_form_action', function($url) use ($nonce) {
            return esc_url(add_query_arg('login_nonce', $nonce, $url));
        }, 10, 1);
    }
*/
    private function check_permissions() {
        if (!current_user_can('manage_options')) {
            add_action('admin_notices', function() {
                echo '<div class="notice notice-error"><p>You do not have sufficient permissions to access this page.</p></div>';
            });
            return false;
        }

        $files = [$this->root_htaccess, $this->admin_htaccess];
        $issues = [];
        $all_writable = true;

        foreach ($files as $file) {
            if (!file_exists($file)) {
                // Attempt to create the file if it doesn’t exist
                if (touch($file)) {
                    chmod($file, 0664); // Set reasonable permissions
                } else {
                    $issues[] = "File $file does not exist and could not be created.";
                    $all_writable = false;
                    continue;
                }
            }

            if (!is_writable($file)) {
                $stat = stat($file);
                $owner = posix_getpwuid($stat['uid'])['name'] ?? $stat['uid'];
                $perms = sprintf('%o', $stat['mode'] & 0777);
                $issues[] = "File $file is not writable. Owner: $owner, Permissions: $perms.";
                // Attempt to fix permissions
                if (@chmod($file, 0664)) {
                    $issues[] = "Permissions for $file adjusted to 664.";
                } else {
                    $all_writable = false;
                }
            }
        }

        if (!empty($issues)) {
            $message = '<p>' . implode('<br>', $issues) . '</p>';
            $message .= '<p><strong>Tip:</strong> On shared hosting, ensure .htaccess files are owned by the web server user (e.g., www-data) or have permissions set to 664. Contact your host to adjust ownership if needed.</p>';
            add_action('admin_notices', function() use ($message) {
                echo '<div class="notice notice-error is-dismissible">' . $message . '</div>';
            });
            $this->log_changes('', "Permission check failed: " . implode("\n", $issues));
        }

        return $all_writable;
    }

    private function write_file_with_fallback($file, $content) {
        // Try direct write first
        if (@file_put_contents($file, $content) !== false) {
            return true;
        }
    
        // Fallback to WP_Filesystem
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
    
        global $wp_filesystem;
        if (!WP_Filesystem()) {
            $this->log_changes('', "WP_Filesystem initialization failed for $file.");
            return false;
        }
    
        if ($wp_filesystem->put_contents($file, $content, 0664)) {
            $this->log_changes('', "Successfully wrote to $file using WP_Filesystem fallback.");
            return true;
        }
    
        $this->log_changes('', "Failed to write to $file even with WP_Filesystem.");
        return false;
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
            if ($this->write_file_with_fallback($target_file, $content)) {
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
                $this->set_admin_notice("Error: Failed to write to .htaccess file. Check server permissions or contact your host.", 'error');
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
    
        // Initialize toggle states based on content
        $toggle_states = [];
        foreach ($this->blocks as $key => $block) {
            $start_marker = '# BEGIN ' . $key;
            $toggle_states[$key] = strpos($content, $start_marker) !== false;
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
                <p style="font-size: 12px; color: #666;"><em>Note: If you can’t save changes on shared hosting, ensure .htaccess files have 664 permissions and are owned by the web server user (e.g., www-data). Use FTP or ask your host to adjust.</em></p>
                <textarea name="htaccess_content" id="htaccess-editor" rows="15" cols="80"><?php echo esc_textarea($content); ?></textarea>
                <div style="width: 100%;">
                    <div style="width: 100%;">
                        <h2>Predefined Blocks (hover button for description)</h2>
                        <div id="predefined-blocks" style="width: 100%;">
                            <?php foreach ($this->blocks as $key => $block) : ?>
                                <?php
                                $class = '';
                                if (strpos($key, 'ADMIN_') === 0 && $current_file !== 'admin') {
                                    $class = 'admin-only hidden';
                                } elseif (strpos($key, 'ADMIN_') === 0) {
                                    $class = 'admin-only';
                                } elseif ($current_file === 'admin') {
                                    $class = 'root-only hidden';
                                }
                                $block_content = str_replace('{{HOME_PATH}}', rtrim(ABSPATH, DIRECTORY_SEPARATOR), $block);
                                $block_content = str_replace('{{HOME_URL}}', home_url(), $block_content);
                                ?>
                                <button type="button" class="block-button <?php echo $class; ?>" data-block="<?php echo esc_attr($key); ?>" title="<?php echo esc_attr($this->block_descriptions[$key]); ?>" data-content="<?php echo esc_attr($block_content); ?>"><?php echo esc_html($key); ?></button>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <div style="width: 100%;">
                        <h2>Security Optimizations (Toggle On/Off)</h2>
                        <?php if ($current_file === 'admin') : ?>
                            <p style="font-size: 12px; color: #666;"><em>Note: Root-level rules (e.g., BLOCK_BAD_BOTS) are applied site-wide from the root .htaccess and are hidden here to avoid redundancy.</em></p>
                        <?php endif; ?>
                        <div id="toggle-blocks" style="width: 100%; column-count: 2; column-gap: 20px; break-inside: avoid;">
                            <?php foreach ($this->blocks as $key => $block) : ?>
                                <?php
                                $toggle_class = '';
                                if (strpos($key, 'ADMIN_') === 0 && $current_file !== 'admin') {
                                    $toggle_class = 'admin-only hidden';
                                } elseif (strpos($key, 'ADMIN_') === 0) {
                                    $toggle_class = 'admin-only';
                                } elseif ($current_file === 'admin') {
                                    $toggle_class = 'root-only hidden';
                                }
                                ?>
                                <div class="toggle-item <?php echo $toggle_class; ?>" style="break-inside: avoid; margin-bottom: 15px;">
                                    <span class="toggle-title"><?php echo esc_html($key); ?></span>
                                    <label class="toggle-switch" style="float: right;">
                                        <input type="checkbox" name="toggle_block[<?php echo esc_attr($key); ?>]" <?php checked($toggle_states[$key]); ?>>
                                        <span class="toggle-slider"></span>
                                    </label>
                                    <p class="toggle-description"><?php echo esc_html($this->block_descriptions[$key]); ?></p>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
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
        <style>
            .admin-only.hidden, .root-only.hidden { display: none; }
            /* Remove admin-only background and border */
            .admin-only { background-color: transparent; border: none; }
            .block-button { margin: 5px; padding: 5px 10px; background-color: #999999; border: 1px solid #666; border-radius: 3px; cursor: pointer; }
            .block-button:hover { background-color: #666666; }
            .block-button.block-added { background-color: #6b9a6b; }
            .block-button.block-not-added { background-color: #999999; }
            #toggle-blocks {
                padding: 10px;
                column-count: 2;
                column-gap: 20px;
                break-inside: avoid; /* Prevents items from breaking across columns */
            }
            .toggle-item {
                overflow: hidden;
                clear: both;
                break-inside: avoid; /* Ensures each toggle item stays intact */
                margin-bottom: 15px; /* Consistent spacing between items */
            }
            .toggle-title {
                float: left;
                font-weight: bold;
                margin-right: 10px;
                line-height: 20px;
            }
            .toggle-switch {
                position: relative;
                display: inline-block;
                width: 40px;
                height: 20px;
                float: right;
                vertical-align: middle;
            }
            .toggle-switch input {
                opacity: 0;
                width: 0;
                height: 0;
            }
            .toggle-slider {
                position: absolute;
                cursor: pointer;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background-color: #ccc;
                -webkit-transition: .4s;
                transition: .4s;
                border-radius: 20px;
            }
            .toggle-slider:before {
                position: absolute;
                content: "";
                height: 16px;
                width: 16px;
                left: 2px;
                bottom: 2px;
                background-color: white;
                -webkit-transition: .4s;
                transition: .4s;
                border-radius: 50%;
            }
            input:checked + .toggle-slider {
                background-color: #2196F3;
            }
            input:checked + .toggle-slider:before {
                -webkit-transform: translateX(20px);
                -ms-transform: translateX(20px);
                transform: translateX(20px);
            }
            .toggle-description {
                clear: both;
                margin-left: 0;
                font-size: 12px;
                color: #666;
                padding-top: 5px;
            }
            .wrap { max-width: 98%; }
            #predefined-blocks { padding: 10px; width: 100%; }
        </style>
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
    
                // Function to update button and toggle states
                function updateStates() {
                    var content = editor.getValue().trim();
                    $('.block-button').each(function() {
                        var blockKey = $(this).data('block');
                        var startMarker = '# BEGIN ' + blockKey;
                        $(this).removeClass('block-added block-not-added')
                               .addClass(content.indexOf(startMarker) !== -1 ? 'block-added' : 'block-not-added');
                    });
                    $('input[name^="toggle_block"]').each(function() {
                        var blockKey = $(this).attr('name').replace('toggle_block[', '').replace(']', '');
                        var startMarker = '# BEGIN ' + blockKey;
                        $(this).prop('checked', content.indexOf(startMarker) !== -1);
                    });
                }
    
                // Initial state update
                updateStates();
    
                // Update states on content change and auto-backup
                editor.on('change', function() {
                    updateStates();
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
    
                // Toggle block on checkbox change
                $('input[name^="toggle_block"]').on('change', function() {
                    var blockKey = $(this).attr('name').replace('toggle_block[', '').replace(']', '');
                    var blockContent = $('.block-button[data-block="' + blockKey + '"]').data('content') || htaccessData.blocks[blockKey];
                    var currentContent = editor.getValue().trim();
                    var startMarker = '# BEGIN ' + blockKey;
                    var endMarker = '# END ' + blockKey;
    
                    if ($(this).is(':checked')) {
                        if (currentContent.indexOf(startMarker) === -1) {
                            var wpStart = currentContent.indexOf('# BEGIN WordPress');
                            var newContent = '';
                            if (wpStart === -1) {
                                newContent = currentContent ? blockContent + '\n' + currentContent : blockContent;
                            } else {
                                newContent = currentContent.substring(0, wpStart).trim() + (currentContent.substring(0, wpStart) ? '\n' : '') + blockContent + '\n' + currentContent.substring(wpStart).trim();
                            }
                            editor.setValue(newContent.trim());
                        }
                    } else {
                        var startIdx = currentContent.indexOf(startMarker);
                        if (startIdx !== -1) {
                            var endIdx = currentContent.indexOf(endMarker, startIdx);
                            if (endIdx !== -1) {
                                endIdx += endMarker.length;
                                currentContent = currentContent.substring(0, startIdx).trim() + '\n' + currentContent.substring(endIdx).trim();
                                editor.setValue(currentContent.trim());
                            }
                        }
                    }
                    updateStates();
                });
    
                // Toggle block on button click
                $('.block-button').on('click', function() {
                    var blockKey = $(this).data('block');
                    var blockContent = $(this).data('content') || htaccessData.blocks[blockKey];
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
                    updateStates();
                });
    
                // Add All Rules button handler
                $('#add-all-rules').on('click', function() {
                    var currentFile = '<?php echo esc_js($current_file); ?>'; // Get current file context
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
                            var blockContent = $('.block-button[data-block="' + blockKey + '"]').data('content') || htaccessData.blocks[blockKey];
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
    
                            // Add block only if it's not an admin rule when editing root
                            if (!(currentFile === 'root' && blockKey.indexOf('ADMIN_') === 0)) {
                                newContent += blockContent + '\n';
                            }
                        }
                    }
    
                    if (wpBlock) {
                        newContent += wpBlock;
                    }
    
                    editor.setValue(newContent.trim());
                    updateStates();
                });
    
                // Delete All Rules button handler
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
    
                    if (wordfenceBlock) {
                        newContent += wordfenceBlock + '\n';
                    }
                    if (wpBlock) {
                        newContent += wpBlock;
                    }
    
                    editor.setValue(newContent.trim());
                    updateStates();
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
        if ($this->write_file_with_fallback($file_to_restore, $content)) {
            $this->log_changes('', $content);
            $this->send_email_notifications("Restored $backup_file to " . ($file_to_restore === $this->admin_htaccess ? 'wp-admin' : 'root') . " .htaccess");
            $this->set_admin_notice("Backup $backup_file restored successfully.", 'success');
            wp_send_json(['success' => true, 'content' => $content]);
        } else {
            $this->set_admin_notice('Failed to restore backup. Check server permissions.', 'error');
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
            error_log('WP HTAccess Manager Test Error: ' . $response->get_error_message());
            return ['success' => false, 'message' => 'Test failed: ' . $response->get_error_message()];
        }
    
        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code === 200) {
            return ['success' => true, 'message' => 'Rules tested successfully (HTTP 200).'];
        } else {
            error_log("WP HTAccess Manager Test Failed: HTTP $status_code");
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