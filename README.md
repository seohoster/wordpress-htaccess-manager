![Lee's .htaccess Manager](https://repository-images.githubusercontent.com/946958652/867ef4f7-8a60-48d0-9b62-23406c56fbcd)

# Lee's .htaccess Manager

A secure, user-friendly WordPress plugin for managing .htaccess files, created by Lee @ Magazinon.ro. This plugin simplifies server configuration management while maintaining robust security measures.

## 🛡️ Key Features

- **Dual .htaccess Management**: Edit both root and wp-admin .htaccess files from a single interface
- **35+ Predefined Rule Blocks**: Ready-to-use configuration blocks for security, performance, and functionality
- **Advanced Security Features**: Brute force protection, nonce validation, rate limiting, and more
- **Syntax Validation**: Prevents saving invalid configurations that could break your site
- **Live Testing**: Test rules before applying them to ensure your site remains accessible
- **Comprehensive Backup System**: Automatic backups stored securely in wp-content/htaccess-backups
- **Change Logging**: Detailed logs of all modifications with timestamps and user information
- **CodeMirror Integration**: Syntax highlighting for easier editing
- **One-Click Solutions**: Add recommended rules or reset to WordPress defaults with a single click
- **Visual Rule Indicators**: Clearly shows which rule blocks are currently active
- **Email Notifications**: Automatic alerts to admin email when .htaccess files are modified

## 🔒 Security Features

- **Protected Backup Location**: Backups stored outside plugin directory in wp-content/htaccess-backups
- **Directory Protection**: Backup directory secured with its own .htaccess rules
- **Permission Verification**: Checks file permissions before allowing modifications
- **Nonce Verification**: All forms and AJAX requests properly secured with WordPress nonces
- **User Capability Checks**: Restricts access to administrators only
- **Input Sanitization**: All inputs properly sanitized to prevent security issues
- **Rate Limiting**: Built-in rate limiting for wp-admin access with cookie-based exemption
- **Login Protection**: Advanced brute force protection with nonce validation
- **Cookie-Based Security**: Implements rate limit exemption cookies for administrators
- **File Access Control**: Prevents unauthorized access to sensitive files

## 📋 Predefined Rule Blocks

### Admin Security
- IP-based access restrictions for wp-admin (configurable IP whitelist)
- HTTP Basic Authentication with AJAX exemption for admin-ajax.php
- PHP execution controls for non-existent files
- Directory listing prevention
- Rate limiting with cookie-based bypass for admins
- HTTPS enforcement for admin area with 301 redirects

### Performance
- LiteSpeed Cache optimization with public caching
- Browser caching configuration (1 year for images, 1 month for CSS/JS)
- GZIP compression with browser compatibility checks
- PHP performance tweaks (memory: 256M, upload: 20M)
- Upload size management with configurable limits

### Security
- wp-config.php access prevention
- XML-RPC blocking for brute force prevention
- XSS and SQL injection protection with query string filtering
- Hotlink prevention with localhost bypass
- Enhanced AI bot blocking:
  - GPTBot, ClaudeBot, CCBot
  - ChatGPT, Anthropic, Cohere
  - Baiduspider, Bytespider
  - FacebookBot, ImagesiftBot
  - HTTrack, Yandex
- User enumeration prevention
- Hidden file protection (except .well-known)
- Sensitive file access control

### Headers & Redirects
- CORS configuration for web fonts (ttf, otf, eot, woff, woff2)
- HSTS implementation with preload support and includeSubDomains
- Comprehensive security headers:
  - X-XSS-Protection
  - X-Content-Type-Options
  - X-Permitted-Cross-Domain-Policies
  - X-Frame-Options
  - Referrer-Policy
- WWW/non-WWW redirection with 301 redirects
- Force HTTPS with permanent redirects

### File Protection
- PHP execution restrictions in uploads directory
- Force download for specific file types (PDF, ZIP, RAR)
- wp-includes PHP execution prevention
- wp-content security with plugin/theme exceptions
- Sensitive file type blocking:
  - Log files (.log)
  - Backup files (.bak)
  - Database files (.sql)
  - Archive files (.zip)

## 💻 Technical Implementation

- Clean, well-documented OOP code structure
- WordPress coding standards compliance
- Efficient backup rotation system
- Graceful error handling with user feedback
- Seamless WordPress admin integration
- Migration support for existing configurations
- Advanced nonce validation system
- Cookie-based security implementations
- Modular rule block architecture

## 🚀 Usage

1. Navigate to "Lee's .htaccess Manager" in your WordPress admin menu
2. Use the tabbed interface to edit root or wp-admin .htaccess
3. Select from predefined rule blocks with hover descriptions
4. Test changes before applying them
5. Manage backups with restore/delete options
6. Monitor active rules through visual indicators

## 🔧 Installation

1. Upload the plugin to your /wp-content/plugins/ directory
2. Activate the plugin through the 'Plugins' menu
3. Access the manager from the admin sidebar
4. Backups will be automatically created in wp-content/htaccess-backups

## ⚙️ Requirements

- WordPress 5.0 or higher
- PHP 7.0 or higher
- Apache web server with mod_rewrite enabled
- Sufficient permissions to edit .htaccess files

## 🌟 Perfect For

- WordPress administrators managing server configurations
- Security professionals implementing hardening measures
- Developers optimizing site performance
- Site owners troubleshooting server-level issues

## 🔄 Changelog

### See change.log file

## 🔜 Upcoming Features

- Settings page for email notifications
- Custom rule templates
- Import/export functionality
- Enhanced rule conflict detection
- Automated security scanning
- Real-time rule testing
- Backup encryption options
- Custom IP whitelist management
- Advanced logging options

## 💬 Support

For questions, feature requests or bug reports, open an issue on GitHub.

Created with ❤️ by Lee @ Magazinon.ro
