# Author: Andrew Xie
# Date: 03/12/2026
# Create users and/or posts, install plugins, or change settings, can also be used to change the admin password

# Create variables
WP_PATH = "/var/www/html/wordpress"

# Create a new WP user (Change username and password if needed)
wp --path="$WP_PATH" user create editor1 editor@lab.local --role=editor --user_pass="Editor@Pass1" --allow-root

# Create new WP post (Change post details)
wp --path="$WP_PATH" post create --post_title="Company Announcement" --post_content="This is an official announcement." --post_status=publish --allow-root

# Install and activate a plugin
wp --path="$WP_PATH" plugin install wordfence --activate --allow-root

# Reset admin password
wp --path="$WP_PATH" user update admin --user_pass="NewAdmin@Pass1" --allow-root

# Update site URL (if needed)
#wp --path="$WP_PATH" option update siteurl "http://10.0.0.60" --allow-root
#wp --path="$WP_PATH" option update home "http://10.0.0.60" --allow-root
