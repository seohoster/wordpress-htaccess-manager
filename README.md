![Lee's .htaccess Manager](https://repository-images.githubusercontent.com/946958652/867ef4f7-8a60-48d0-9b62-23406c56fbcd)

# Lee's .htaccess Manager

A secure, user-friendly WordPress plugin for managing .htaccess files, created by Lee @ Magazinon.ro.

## 🛡️ Key Features

- **Dual .htaccess Management**: Edit both root and wp-admin .htaccess files from a single interface
- **30+ Predefined Rule Blocks**: Ready-to-use configuration blocks for security, performance, and functionality
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
- **Nonce Verification**: All forms and AJAX requests properly secured
- **User Capability Checks**: Restricts access to administrators only
- **Input Sanitization**: All inputs properly sanitized to prevent security issues
- **Rate Limiting**: Built-in rate limiting for wp-admin access
- **Login Protection**: Advanced brute force protection with nonce validation

## 📋 Predefined Rule Blocks

### Admin Security
- IP-based access restrictions for wp-admin
- HTTP Basic Authentication support
- PHP execution controls
- Directory listing prevention
- Rate limiting implementation
- HTTPS enforcement

### Performance
- LiteSpeed Cache optimization
- Browser caching configuration
- GZIP compression
- PHP performance tweaks
- Upload size management

### Security
- wp-config.php protection
- XML-RPC blocking
- XSS and SQL injection protection
- Hotlink prevention
- AI bot blocking (GPTBot, ClaudeBot, Google-Extended)
- User enumeration prevention
- Hidden file protection
- Sensitive file access control

### Headers & Redirects
- CORS configuration for fonts and assets
- HSTS implementation
- Security headers setup
- WWW/non-WWW redirection
- Force HTTPS

### File Protection
- PHP execution restrictions in uploads
- Force download for specific file types
- wp-includes protection
- wp-content security rules

## 💻 Technical Implementation

- Clean, well-documented OOP code structure
- WordPress coding standards compliance
- Efficient backup rotation system
- Graceful error handling
- Seamless WordPress admin integration
- Migration support for existing configurations

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

### Version 1.9.40
- Added advanced brute force protection with nonce validation
- Enhanced rate limiting functionality
- Improved backup directory security
- Added new AI bot blocking rules
- Fixed login form nonce implementation
- Added more predefined security rules

## 🔜 Upcoming Features

- Settings page for email notifications
- Custom rule templates
- Import/export functionality
- Enhanced rule conflict detection
- Automated security scanning

## 💬 Support

For questions, feature requests or bug reports, please visit [Magazinon.ro](https://www.magazinon.ro) or open an issue on GitHub.

Created with ❤️ by Lee @ Magazinon.ro
