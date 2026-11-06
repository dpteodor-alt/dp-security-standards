<?php
/**
 * DP-SEC-011 good: nonce, then capability, then the write.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Saves the color setting on admin_init.
 */
function dp_save_settings() {
	if ( ! isset( $_POST['dp_settings_nonce'], $_POST['dp_color'] ) ) {
		return;
	}
	if ( ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['dp_settings_nonce'] ) ), 'dp_save_settings' ) ) {
		return;
	}
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	update_option( 'dp_color', sanitize_hex_color( wp_unslash( $_POST['dp_color'] ) ) );
}
add_action( 'admin_init', 'dp_save_settings' );
