<?php
/**
 * DP-SEC-011 bad: form processing without a nonce.
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
	if ( ! current_user_can( 'manage_options' ) || ! isset( $_POST['dp_color'] ) ) { // expect: WordPress.Security.NonceVerification.Missing
		return;
	}
	update_option( 'dp_color', sanitize_hex_color( wp_unslash( $_POST['dp_color'] ) ) ); // expect: WordPress.Security.NonceVerification.Missing
}
add_action( 'admin_init', 'dp_save_settings' );
