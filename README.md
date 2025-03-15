# Lee's .htaccess Manager

## A secure, user-friendly WordPress plugin for managing .htaccess files.
## Lee's .htaccess Manager is a robust WordPress plugin designed to simplify the management of both root and wp-admin .htaccess files through an intuitive interface.
## Created with security and usability in mind, this plugin allows administrators to safely modify server configurations without risking site breakage.

🛡️ Key Features
Dual .htaccess Management: Edit both root and wp-admin .htaccess files from a single interface
Predefined Rule Blocks: 25+ ready-to-use configuration blocks for security, performance, and functionality
Syntax Validation: Prevents saving invalid configurations that could break your site
Live Testing: Test rules before applying them to ensure your site remains accessible
Comprehensive Backup System: Automatic backups stored securely in wp-content directory
Change Logging: Detailed logs of all modifications with timestamps and user information
CodeMirror Integration: Syntax highlighting for easier editing
One-Click Solutions: Add all recommended rules or reset to WordPress defaults with a single click
Visual Rule Indicators: Clearly shows which rule blocks are currently active
Email Notifications: Automatic alerts to admin email when .htaccess files are modified

🔒 Security Features
Protected Backup Location: Backups stored outside plugin directory in wp-content/htaccess-backups
Directory Protection: Backup directory secured with its own .htaccess rules
Permission Verification: Checks file permissions before allowing modifications
Nonce Verification: All forms and AJAX requests properly secured
User Capability Checks: Restricts access to administrators only
Input Sanitization: All inputs properly sanitized to prevent security issues

📋 Predefined Rule Blocks
Browser caching optimization
GZIP compression
Security headers implementation
XML-RPC blocking
PHP execution restrictions
Directory browsing prevention
HTTPS enforcement
AI bot blocking (GPTBot, ClaudeBot)
Hotlink protection
XSS and SQL injection protection
User enumeration prevention
And many more...

💻 Technical Implementation
Clean, well-documented OOP code structure
WordPress coding standards compliance
Efficient backup rotation to prevent storage bloat
Graceful error handling with descriptive messages
Seamless integration with WordPress admin interface
Migration support for existing .htaccess configurations

🚀 Usage
Simply navigate to "Lee's .htaccess Manager" in your WordPress admin menu. The interface provides:
A tabbed editor for both root and wp-admin .htaccess files
Predefined rule blocks with hover descriptions
Testing functionality to validate changes before saving
Backup management with restore/delete options
Clear visual indicators of active rules

🔧 Installation
Upload the plugin to your /wp-content/plugins/ directory
Activate the plugin through the 'Plugins' menu in WordPress
Access the manager from the admin sidebar
Backups are automatically created in wp-content/htaccess-backups

⚙️ Requirements
WordPress 5.0 or higher
PHP 7.0 or higher
Apache web server with mod_rewrite enabled
Sufficient permissions to edit .htaccess files

🌟 Perfect For
WordPress administrators who need to modify .htaccess without FTP access
Security professionals implementing hardening measures
Developers optimizing site performance through server configurations
Site owners troubleshooting server-level issues

🔄 Changelog
Version 1.9.35
Moved backup directory to wp-content/htaccess-backups for enhanced security
Added directory protection for backup files
Implemented backup rotation to prevent excessive disk usage

🔜 Upcoming Features
Settings page to toggle email notifications
Custom rule templates
Import/export functionality for .htaccess configurations
Enhanced rule conflict detection

💬 Support
For questions, feature requests or bug reports, please open an issue on GitHub or visit Magazinon.ro for additional resources and support.
Created with ❤️ by Lee @ Magazinon.ro